#!/usr/bin/env python3
"""clawdctl - interactive EC2 lifecycle helper (menu-driven, CLI-only)

Design goals:
- Safe-by-default destructive actions (explicit confirmation)
- Extensible structure (service layer + menu layer)
- Minimal dependencies (uses AWS CLI + standard library)

Defaults (override via environment):
- PROFILE=molt
- REGION=us-east-2
- IAM_INSTANCE_PROFILE_NAME=AmazonSSMRoleForMolt
- PROJECT_TAG=Project=clawd
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import fcntl


# =========================
# Config
# =========================
PROFILE = os.getenv("PROFILE", "molt")
REGION = os.getenv("REGION", "us-east-2")
IAM_INSTANCE_PROFILE_NAME = os.getenv("IAM_INSTANCE_PROFILE_NAME", "AmazonSSMRoleForMolt")

PROJECT_TAG_KEY = os.getenv("PROJECT_TAG_KEY", "Project")
PROJECT_TAG_VALUE = os.getenv("PROJECT_TAG_VALUE", "clawd")
CREATED_BY_VALUE = os.getenv("CREATED_BY", "clawdctl")
DEFAULT_NAME_PREFIX = os.getenv("DEFAULT_NAME_PREFIX", "clawd")

INSTANCE_TYPE = os.getenv("INSTANCE_TYPE", "t4g.small")
ROOT_VOL_GB = int(os.getenv("ROOT_VOL_GB", "20"))
ROOT_VOL_TYPE = os.getenv("ROOT_VOL_TYPE", "gp3")
MUTATION_LOCK_FILE = os.getenv("CLAWDCTL_LOCK_FILE", "/tmp/clawdctl.lock")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "./molt-key.pem")
SSH_USER = os.getenv("SSH_USER", "ubuntu")
CLAWD_BOOTSTRAP_SCRIPT = os.getenv("CLAWD_BOOTSTRAP_SCRIPT", "./clawd-bootstrap.sh")
CLAWD_BOOTSTRAP_REMOTE_PATH = os.getenv("CLAWD_BOOTSTRAP_REMOTE_PATH", "/tmp/clawd-bootstrap.sh")
ACTION_CHOICES = ("l", "t", "s", "h", "n", "b", "x")
ACTION_FLAG_BY_KEY = {
    "l": "--list",
    "t": "--terminate",
    "s": "--ssm",
    "h": "--ssh",
    "n": "--launch",
    "b": "--bootstrap",
    "x": "--reset",
}

# Prefer Ubuntu 24.04 ARM64 (Canonical public SSM parameter); fallback to 22.04
UBUNTU_AMI_PARAMS = [
    "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id",
    "/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp3/ami-id",
]


# =========================
# Utilities
# =========================

def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def die(msg: str, code: int = 1) -> None:
    eprint(f"ERROR: {msg}")
    raise SystemExit(code)


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def prompt(msg: str) -> str:
    return input(msg)


def prompt_yes_no(msg: str, default_no: bool = True) -> bool:
    suffix = " [y/N] " if default_no else " [Y/n] "
    ans = input(msg + suffix).strip().lower()
    if not ans:
        return not default_no
    return ans in {"y", "yes"}


def require_aws_cli() -> None:
    try:
        subprocess.run(["aws", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        die("aws CLI not found or not runnable. Install/configure AWS CLI first.")


def get_current_public_ipv4() -> str:
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
            ip = resp.read().decode("utf-8").strip()
    except Exception as ex:
        raise RuntimeError(f"failed to detect current public IP: {ex}") from ex
    if not ip:
        raise RuntimeError("failed to detect current public IP (empty response)")
    return ip


def run_interactive(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run an interactive subprocess while ignoring Ctrl+C in clawdctl itself."""
    old_sigint = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, lambda _signum, _frame: None)
        return subprocess.run(cmd, text=True)
    finally:
        signal.signal(signal.SIGINT, old_sigint)


def tracked_reload_files() -> List[str]:
    return [
        os.path.realpath(__file__),
        os.path.realpath(CLAWD_BOOTSTRAP_SCRIPT),
    ]


def snapshot_reload_state(paths: Sequence[str]) -> Dict[str, float]:
    state: Dict[str, float] = {}
    for path in paths:
        try:
            state[path] = float(os.path.getmtime(path))
        except OSError:
            state[path] = -1.0
    return state


def changed_reload_files(state: Dict[str, float]) -> List[str]:
    current = snapshot_reload_state(list(state.keys()))
    return [path for path, old_mtime in state.items() if current.get(path, -1.0) != old_mtime]


def reload_self(action: Optional[str] = None) -> None:
    eprint("Reloading clawdctl to pick up local changes...")
    args: List[str] = [sys.executable, sys.argv[0]]
    if action:
        flag = ACTION_FLAG_BY_KEY.get(action)
        if flag:
            args.append(flag)
    os.execv(sys.executable, args)


@contextmanager
def mutation_lock() -> Any:
    """Serialize destructive/mutating operations across parallel clawdctl processes."""
    with open(MUTATION_LOCK_FILE, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# =========================
# AWS CLI wrapper
# =========================

class AwsCli:
    def __init__(self, profile: str, region: str):
        self.profile = profile
        self.region = region

    def _base_cmd(self) -> List[str]:
        return ["aws", "--profile", self.profile, "--region", self.region]

    def run_json(self, args: Sequence[str], *, quiet: bool = False) -> Any:
        cmd = self._base_cmd() + list(args) + ["--output", "json"]
        if not quiet:
            eprint("$", " ".join(shlex.quote(c) for c in cmd))
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"aws command failed: {' '.join(args)}")
        out = proc.stdout.strip()
        if not out:
            return None
        return json.loads(out)

    def run_text(self, args: Sequence[str], *, quiet: bool = False) -> str:
        cmd = self._base_cmd() + list(args) + ["--output", "text"]
        if not quiet:
            eprint("$", " ".join(shlex.quote(c) for c in cmd))
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"aws command failed: {' '.join(args)}")
        return proc.stdout.strip()


# =========================
# Domain models
# =========================

@dataclass
class InstanceRow:
    instance_id: str
    name: str
    instance_type: str
    state: str
    launch_time: str
    private_ip: str
    public_ip: str
    vpc_id: str
    subnet_id: str


# =========================
# EC2/SSM operations (extensible service layer)
# =========================

class ClawdService:
    def __init__(self, aws: AwsCli):
        self.aws = aws

    # ------- Discovery -------
    def list_running_instances(self) -> List[InstanceRow]:
        # Use a single describe-instances call, then parse in Python
        data = self.aws.run_json(
            [
                "ec2",
                "describe-instances",
            ],
            quiet=True,
        )

        rows: List[InstanceRow] = []
        for r in (data or {}).get("Reservations", []):
            for inst in r.get("Instances", []):
                tags = {t.get("Key"): t.get("Value") for t in inst.get("Tags", []) if t.get("Key")}
                rows.append(
                    InstanceRow(
                        instance_id=inst.get("InstanceId", "-") or "-",
                        name=tags.get("Name", "-") or "-",
                        instance_type=inst.get("InstanceType", "-") or "-",
                        state=(inst.get("State", {}) or {}).get("Name", "-") or "-",
                        launch_time=inst.get("LaunchTime", "-") or "-",
                        private_ip=inst.get("PrivateIpAddress", "-") or "-",
                        public_ip=inst.get("PublicIpAddress", "-") or "-",
                        vpc_id=inst.get("VpcId", "-") or "-",
                        subnet_id=inst.get("SubnetId", "-") or "-",
                    )
                )

        # sort by launch time desc (newest first), then id
        def sort_key(x: InstanceRow) -> Tuple[str, str]:
            return (x.launch_time, x.instance_id)

        rows.sort(key=sort_key, reverse=True)
        return rows

    # ------- Termination -------
    def terminate_instances(self, instance_ids: List[str]) -> None:
        if not instance_ids:
            return
        with mutation_lock():
            sg_ids = self._collect_security_groups_for_instances(instance_ids)
            self.aws.run_json(["ec2", "terminate-instances", "--instance-ids", *instance_ids], quiet=True)
            eprint("Waiting for instances to reach terminated state...")
            self.aws.run_text(["ec2", "wait", "instance-terminated", "--instance-ids", *instance_ids], quiet=True)
            self._cleanup_tool_security_groups(sg_ids)

    def _collect_security_groups_for_instances(self, instance_ids: List[str]) -> List[str]:
        if not instance_ids:
            return []
        data = self.aws.run_json(
            ["ec2", "describe-instances", "--instance-ids", *instance_ids],
            quiet=True,
        )
        sg_ids: set[str] = set()
        for r in (data or {}).get("Reservations", []):
            for inst in r.get("Instances", []):
                for sg in inst.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId")
                    if sg_id:
                        sg_ids.add(str(sg_id))
        return sorted(sg_ids)

    def get_instance_security_groups(self, instance_id: str) -> List[str]:
        data = self.aws.run_json(["ec2", "describe-instances", "--instance-ids", instance_id], quiet=True)
        sg_ids: set[str] = set()
        for r in (data or {}).get("Reservations", []):
            for inst in r.get("Instances", []):
                for sg in inst.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId")
                    if sg_id:
                        sg_ids.add(str(sg_id))
        return sorted(sg_ids)

    def _cleanup_tool_security_groups(self, sg_ids: List[str]) -> None:
        if not sg_ids:
            return
        removed = 0
        for sg_id in sg_ids:
            try:
                sg_resp = self.aws.run_json(["ec2", "describe-security-groups", "--group-ids", sg_id], quiet=True)
            except RuntimeError:
                continue

            groups = (sg_resp or {}).get("SecurityGroups", [])
            if not groups:
                continue
            sg = groups[0]
            tags = {t.get("Key"): t.get("Value") for t in sg.get("Tags", []) if t.get("Key")}
            if tags.get("CreatedBy") != CREATED_BY_VALUE:
                continue

            enis = self.aws.run_json(
                ["ec2", "describe-network-interfaces", "--filters", f"Name=group-id,Values={sg_id}"],
                quiet=True,
            )
            if (enis or {}).get("NetworkInterfaces"):
                continue

            try:
                self.aws.run_json(["ec2", "delete-security-group", "--group-id", sg_id], quiet=True)
                removed += 1
            except RuntimeError as ex:
                eprint(f"Warning: could not delete security group {sg_id}: {ex}")

        if removed:
            eprint(f"Deleted {removed} unused clawdctl security group(s).")

    # ------- Launch helpers -------
    def get_default_vpc_id(self) -> str:
        vpcs = self.aws.run_json(["ec2", "describe-vpcs", "--filters", "Name=isDefault,Values=true"], quiet=True)
        vpc_list = (vpcs or {}).get("Vpcs", [])
        if not vpc_list:
            die(f"Could not find a default VPC in {REGION}.")
        vpc_id = vpc_list[0].get("VpcId")
        if not vpc_id:
            die(f"Default VPC missing VpcId in {REGION}.")
        return str(vpc_id)

    def get_default_subnet_id_for_vpc(self, vpc_id: str) -> str:
        subs = self.aws.run_json(
            [
                "ec2",
                "describe-subnets",
                "--filters",
                f"Name=vpc-id,Values={vpc_id}",
                "Name=default-for-az,Values=true",
            ],
            quiet=True,
        )
        sub_list = (subs or {}).get("Subnets", [])
        if not sub_list:
            die(f"Could not find a default-for-az subnet in VPC {vpc_id}.")
        subnet_id = sub_list[0].get("SubnetId")
        if not subnet_id:
            die(f"Default subnet missing SubnetId in VPC {vpc_id}.")
        return str(subnet_id)

    def resolve_ubuntu_arm_ami(self) -> str:
        for param in UBUNTU_AMI_PARAMS:
            try:
                resp = self.aws.run_json(["ssm", "get-parameter", "--name", param], quiet=True)
                ami = ((resp or {}).get("Parameter", {}) or {}).get("Value")
                if ami:
                    return str(ami)
            except Exception:
                continue
        die("Could not resolve a Canonical Ubuntu ARM AMI via SSM parameters.")
        raise AssertionError("unreachable")

    def create_lockdown_security_group(self, vpc_id: str) -> str:
        sg_name = f"{DEFAULT_NAME_PREFIX}-noinbound-{now_stamp()}"
        desc = "No inbound; all outbound; created by clawdctl"
        resp = self.aws.run_json(
            [
                "ec2",
                "create-security-group",
                "--group-name",
                sg_name,
                "--description",
                desc,
                "--vpc-id",
                vpc_id,
            ],
            quiet=True,
        )
        sg_id = (resp or {}).get("GroupId")
        if not sg_id:
            die("Failed to create security group (no GroupId returned).")

        # Tag SG
        self.tag_resources(
            [str(sg_id)],
            {
                PROJECT_TAG_KEY: PROJECT_TAG_VALUE,
                "Name": sg_name,
                "CreatedBy": CREATED_BY_VALUE,
            },
        )
        return str(sg_id)

    def tag_resources(self, resource_ids: List[str], tags: Dict[str, str]) -> None:
        tag_args: List[str] = []
        for k, v in tags.items():
            tag_args.append(f"Key={k},Value={v}")
        self.aws.run_json(["ec2", "create-tags", "--resources", *resource_ids, "--tags", *tag_args], quiet=True)

    def launch_instance(self) -> str:
        with mutation_lock():
            vpc_id = self.get_default_vpc_id()
            subnet_id = self.get_default_subnet_id_for_vpc(vpc_id)
            sg_id = self.create_lockdown_security_group(vpc_id)
            ami = self.resolve_ubuntu_arm_ami()

            stamp = now_stamp()
            name = f"{DEFAULT_NAME_PREFIX}-{stamp}"

            user_data = """#!/bin/bash
set -euo pipefail

# Ensure snapd is available (usually is), then install SSM agent
if ! command -v snap >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y snapd
fi

snap install amazon-ssm-agent --classic || true

# Some images may already include the agent; try both service names
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null || true
systemctl start  snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null || true

systemctl enable amazon-ssm-agent 2>/dev/null || true
systemctl start  amazon-ssm-agent 2>/dev/null || true
"""

            # Use a temp file because aws CLI supports file:// for user-data
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(user_data)
                user_data_path = f.name

            try:
                eprint("\nLaunching new instance:")
                eprint(f"  AMI:           {ami}")
                eprint(f"  Type:          {INSTANCE_TYPE}")
                eprint(f"  Subnet:        {subnet_id} (default subnet)")
                eprint(f"  SecurityGroup: {sg_id} (no inbound)")
                eprint(f"  Root:          {ROOT_VOL_GB}GB {ROOT_VOL_TYPE}")
                eprint(f"  IAM Profile:   {IAM_INSTANCE_PROFILE_NAME}")
                eprint("  Public IPv4:   enabled")
                eprint(f"  Tags:          {PROJECT_TAG_KEY}={PROJECT_TAG_VALUE}, Name={name}")

                network_if = json.dumps(
                    [
                        {
                            "DeviceIndex": 0,
                            "SubnetId": subnet_id,
                            "AssociatePublicIpAddress": True,
                            "Groups": [sg_id],
                        }
                    ]
                )

                block_map = json.dumps(
                    [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "VolumeSize": ROOT_VOL_GB,
                                "VolumeType": ROOT_VOL_TYPE,
                                "DeleteOnTermination": True,
                            },
                        }
                    ]
                )

                tag_specs = [
                    f"ResourceType=instance,Tags=[{{Key={PROJECT_TAG_KEY},Value={PROJECT_TAG_VALUE}}},{{Key=Name,Value={name}}},{{Key=CreatedBy,Value={CREATED_BY_VALUE}}}]",
                    f"ResourceType=volume,Tags=[{{Key={PROJECT_TAG_KEY},Value={PROJECT_TAG_VALUE}}},{{Key=Name,Value={name}-root}} ,{{Key=CreatedBy,Value={CREATED_BY_VALUE}}}]",
                ]

                resp = self.aws.run_json(
                    [
                        "ec2",
                        "run-instances",
                        "--image-id",
                        ami,
                        "--instance-type",
                        INSTANCE_TYPE,
                        "--iam-instance-profile",
                        f"Name={IAM_INSTANCE_PROFILE_NAME}",
                        "--metadata-options",
                        "HttpTokens=required,HttpEndpoint=enabled",
                        "--network-interfaces",
                        network_if,
                        "--block-device-mappings",
                        block_map,
                        "--user-data",
                        f"file://{user_data_path}",
                        "--tag-specifications",
                        *tag_specs,
                    ],
                    quiet=True,
                )

                inst = ((resp or {}).get("Instances", []) or [{}])[0]
                instance_id = inst.get("InstanceId")
                if not instance_id:
                    die("Instance launch failed (no InstanceId returned).")

                eprint(f"\nLaunched instance: {instance_id}")
                eprint("\nSSM (Session Manager) command:")
                eprint(f"  aws --profile {PROFILE} --region {REGION} ssm start-session --target {instance_id}\n")
                eprint("Tip: it may take ~1–3 minutes before the instance shows as 'Online' in SSM.\n")

                return str(instance_id)

            finally:
                try:
                    os.unlink(user_data_path)
                except Exception:
                    pass

    # ------- SSM status -------
    def get_ssm_ping_status(self, instance_id: str) -> Optional[str]:
        try:
            resp = self.aws.run_json(
                [
                    "ssm",
                    "describe-instance-information",
                    "--filters",
                    f"Key=InstanceIds,Values={instance_id}",
                ],
                quiet=True,
            )
            lst = (resp or {}).get("InstanceInformationList", [])
            if not lst:
                return None
            return str(lst[0].get("PingStatus"))
        except Exception:
            return None

    def wait_for_ssm_online(self, instance_id: str, *, poll_seconds: int = 5) -> None:
        eprint(f"Waiting for SSM PingStatus=Online for {instance_id} (Ctrl+C to skip)...")
        while True:
            status = self.get_ssm_ping_status(instance_id)
            if status == "Online":
                eprint(f"SSM is Online for {instance_id}")
                return
            time.sleep(poll_seconds)

    def _run_ssm_shell_commands(
        self,
        instance_id: str,
        commands: List[str],
        *,
        comment: str,
        step: str,
        timeout_seconds: int = 900,
        poll_seconds: int = 2,
    ) -> None:
        params = json.dumps({"commands": commands})
        resp = self.aws.run_json(
            [
                "ssm",
                "send-command",
                "--document-name",
                "AWS-RunShellScript",
                "--instance-ids",
                instance_id,
                "--comment",
                comment,
                "--parameters",
                params,
            ],
            quiet=True,
        )
        command_id = ((resp or {}).get("Command", {}) or {}).get("CommandId")
        if not command_id:
            raise RuntimeError("failed to start SSM command (missing CommandId)")

        deadline = time.time() + timeout_seconds
        while True:
            inv = self.aws.run_json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    str(command_id),
                    "--instance-id",
                    instance_id,
                ],
                quiet=True,
            )
            status = str((inv or {}).get("Status", "Unknown"))
            if status == "Success":
                return
            if status in {"Pending", "InProgress", "Delayed"}:
                if time.time() >= deadline:
                    raise RuntimeError(
                        f"SSM {step} timed out (status={status}, command_id={command_id}). "
                        f"Inspect with: aws --profile {PROFILE} --region {REGION} ssm get-command-invocation "
                        f"--command-id {command_id} --instance-id {instance_id}"
                    )
                time.sleep(poll_seconds)
                continue
            stdout = str((inv or {}).get("StandardOutputContent", "")).strip()
            stderr = str((inv or {}).get("StandardErrorContent", "")).strip()
            stdout_snip = stdout[-1200:] if stdout else ""
            stderr_snip = stderr[-1200:] if stderr else ""
            msg = (
                f"SSM {step} failed (status={status}, command_id={command_id}). "
                f"Inspect with: aws --profile {PROFILE} --region {REGION} ssm get-command-invocation "
                f"--command-id {command_id} --instance-id {instance_id}"
            )
            if stderr_snip:
                msg += f"\n--- stderr (last {len(stderr_snip)} chars) ---\n{stderr_snip}"
            if stdout_snip:
                msg += f"\n--- stdout (last {len(stdout_snip)} chars) ---\n{stdout_snip}"
            raise RuntimeError(msg)

    def copy_bootstrap_script_via_ssm(self, instance_id: str) -> None:
        if not os.path.isfile(CLAWD_BOOTSTRAP_SCRIPT):
            raise RuntimeError(f"bootstrap script not found: {CLAWD_BOOTSTRAP_SCRIPT}")
        with open(CLAWD_BOOTSTRAP_SCRIPT, "r", encoding="utf-8") as f:
            script_body = f.read()

        marker = f"CLAWD_BOOTSTRAP_{now_stamp().replace('-', '_')}"
        write_cmd = "\n".join(
            [
                f"cat > {CLAWD_BOOTSTRAP_REMOTE_PATH} <<'{marker}'",
                script_body.rstrip("\n"),
                marker,
                f"chmod +x {CLAWD_BOOTSTRAP_REMOTE_PATH}",
            ]
        )
        eprint(f"Copying bootstrap script to {instance_id} via SSM...")
        self._run_ssm_shell_commands(
            instance_id,
            [write_cmd],
            comment="clawdctl copy bootstrap script",
            step="copy bootstrap script",
        )

    def run_bootstrap_script_via_ssm(self, instance_id: str) -> None:
        eprint(f"Running bootstrap script on {instance_id} via SSM...")
        self._run_ssm_shell_commands(
            instance_id,
            [f"bash {CLAWD_BOOTSTRAP_REMOTE_PATH}"],
            comment="clawdctl run bootstrap script",
            step="run bootstrap script",
        )
        eprint("Bootstrap completed.")

    def start_ssm_session(self, instance_id: str) -> None:
        cmd = self.aws._base_cmd() + ["ssm", "start-session", "--target", instance_id]
        eprint("$", " ".join(shlex.quote(c) for c in cmd))
        proc = run_interactive(cmd)
        # Ctrl+C from an interactive session commonly returns 130.
        if proc.returncode in (0, 130):
            return
        if proc.returncode != 0:
            raise RuntimeError(f"failed to start SSM session for {instance_id}")

    def ssh_with_temporary_ingress(self, instance_id: str, public_ip: str) -> None:
        if not os.path.isfile(SSH_KEY_PATH):
            raise RuntimeError(f"SSH key file not found: {SSH_KEY_PATH}")
        if not public_ip or public_ip == "-":
            raise RuntimeError(f"instance {instance_id} does not have a public IP")

        client_ip = get_current_public_ipv4()
        cidr = f"{client_ip}/32"
        added_rules: List[str] = []

        with mutation_lock():
            sg_ids = self.get_instance_security_groups(instance_id)
            if not sg_ids:
                raise RuntimeError(f"no security groups found for instance {instance_id}")

            for sg_id in sg_ids:
                try:
                    self.aws.run_json(
                        [
                            "ec2",
                            "authorize-security-group-ingress",
                            "--group-id",
                            sg_id,
                            "--protocol",
                            "tcp",
                            "--port",
                            "22",
                            "--cidr",
                            cidr,
                        ],
                        quiet=True,
                    )
                    added_rules.append(sg_id)
                except RuntimeError as ex:
                    msg = str(ex)
                    if "InvalidPermission.Duplicate" in msg:
                        eprint(f"SSH rule already exists on {sg_id} for {cidr}; will not remove it later.")
                        continue
                    raise

        ssh_cmd = [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{SSH_USER}@{public_ip}",
        ]
        eprint("$", " ".join(shlex.quote(c) for c in ssh_cmd))

        try:
            proc = run_interactive(ssh_cmd)
            # Treat Ctrl+C as a normal user-cancel for interactive SSH.
            if proc.returncode in (0, 130):
                return
            if proc.returncode != 0:
                raise RuntimeError(f"ssh exited with status {proc.returncode}")
        finally:
            with mutation_lock():
                for sg_id in added_rules:
                    try:
                        self.aws.run_json(
                            [
                                "ec2",
                                "revoke-security-group-ingress",
                                "--group-id",
                                sg_id,
                                "--protocol",
                                "tcp",
                                "--port",
                                "22",
                                "--cidr",
                                cidr,
                            ],
                            quiet=True,
                        )
                    except RuntimeError as ex:
                        eprint(f"Warning: could not remove temporary SSH rule from {sg_id}: {ex}")


# =========================
# Presentation / menu
# =========================

def format_table(rows: List[List[str]], headers: List[str]) -> str:
    cols = list(zip(*([headers] + rows))) if rows else [headers]
    widths = [max(len(str(c)) for c in col) for col in cols]

    def fmt_row(r: List[str]) -> str:
        return "  ".join(str(c).ljust(w) for c, w in zip(r, widths))

    out = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    out += [fmt_row(r) for r in rows]
    return "\n".join(out)


def show_instances(instances: List[InstanceRow]) -> None:
    if not instances:
        eprint(f"No instances found in {REGION} (profile: {PROFILE}).")
        return

    rows: List[List[str]] = []
    for idx, i in enumerate(instances, start=1):
        rows.append(
            [
                str(idx),
                i.instance_id,
                i.name,
                i.state,
                i.instance_type,
                i.launch_time,
                i.public_ip,
                i.private_ip,
            ]
        )

    eprint("\nAll instances:")
    eprint(format_table(rows, ["#", "InstanceId", "Name", "State", "Type", "LaunchTime", "PublicIP", "PrivateIP"]))


def choose_instances(instances: List[InstanceRow]) -> List[str]:
    """Allow selecting instances by index or 'all'."""
    if not instances:
        return []

    eprint("\nSelect instances to terminate:")
    eprint("- Enter 'all' to select all")
    eprint("- Or enter a comma-separated list like: 1,2,5")
    eprint("- Or enter a range like: 1-3")

    raw = prompt("Selection: ").strip().lower()
    if raw == "all":
        return [i.instance_id for i in instances]

    selected: set[int] = set()
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                start = int(a)
                end = int(b)
            except ValueError:
                die(f"Invalid range: {p}")
            if start < 1 or end < 1 or start > len(instances) or end > len(instances):
                die(f"Range out of bounds: {p}")
            for n in range(min(start, end), max(start, end) + 1):
                selected.add(n)
        else:
            try:
                n = int(p)
            except ValueError:
                die(f"Invalid selection: {p}")
            if n < 1 or n > len(instances):
                die(f"Selection out of bounds: {n}")
            selected.add(n)

    return [instances[n - 1].instance_id for n in sorted(selected)]


def choose_single_instance(instances: List[InstanceRow]) -> Optional[InstanceRow]:
    if not instances:
        return None

    raw = prompt("Instance number for SSM session: ").strip()
    try:
        n = int(raw)
    except ValueError:
        die(f"Invalid selection: {raw}")
    if n < 1 or n > len(instances):
        die(f"Selection out of bounds: {n}")
    return instances[n - 1]


def menu_title() -> None:
    eprint("\n====================")
    eprint(" clawdctl (python)")
    eprint("====================")
    eprint(f"Profile: {PROFILE}   Region: {REGION}")
    eprint(f"Project tag: {PROJECT_TAG_KEY}={PROJECT_TAG_VALUE}")


def maybe_auto_reload_for_action(
    reload_state: Optional[Dict[str, float]],
    action_key: str,
    action_name: str,
) -> None:
    if reload_state is None:
        return
    changed = changed_reload_files(reload_state)
    if changed:
        eprint(f"Detected local file changes before {action_name}.")
        for path in changed:
            eprint(f"  - {path}")
        reload_self(action_key)


def run_action(
    svc: ClawdService,
    choice: str,
    *,
    reload_state: Optional[Dict[str, float]],
    pause_after: bool,
) -> bool:
    def pause() -> None:
        if pause_after:
            prompt("\nPress Enter to continue...")

    if choice == "l":
        instances = svc.list_running_instances()
        show_instances(instances)
        pause()
        return False

    if choice == "t":
        maybe_auto_reload_for_action(reload_state, "t", "terminate")
        instances = svc.list_running_instances()
        show_instances(instances)
        if not instances:
            pause()
            return False

        ids = choose_instances(instances)
        if not ids:
            eprint("No instances selected.")
            pause()
            return False

        eprint("\nAbout to terminate:")
        for i in ids:
            eprint(f"  - {i}")

        confirm = prompt("\nType TERMINATE to confirm: ").strip()
        if confirm != "TERMINATE":
            eprint("Canceled. No instances terminated.")
            pause()
            return False

        svc.terminate_instances(ids)
        eprint("Termination initiated.")
        pause()
        return False

    if choice == "s":
        instances = svc.list_running_instances()
        show_instances(instances)
        if not instances:
            pause()
            return False

        eprint("\nSelect one instance for Session Manager:")
        selected = choose_single_instance(instances)
        if selected is None:
            pause()
            return False
        if selected.state != "running":
            eprint(f"Instance {selected.instance_id} is '{selected.state}'. It must be running for SSM.")
            pause()
            return False

        status = svc.get_ssm_ping_status(selected.instance_id)
        if status != "Online":
            eprint(f"SSM PingStatus is {status or 'Unavailable'} for {selected.instance_id}.")
            if prompt_yes_no("Wait for SSM to become Online?", default_no=True):
                svc.wait_for_ssm_online(selected.instance_id)

        svc.start_ssm_session(selected.instance_id)
        pause()
        return False

    if choice == "h":
        instances = svc.list_running_instances()
        show_instances(instances)
        if not instances:
            pause()
            return False

        eprint("\nSelect one instance for SSH:")
        selected = choose_single_instance(instances)
        if selected is None:
            pause()
            return False
        if selected.state != "running":
            eprint(f"Instance {selected.instance_id} is '{selected.state}'. It must be running for SSH.")
            pause()
            return False
        if selected.public_ip == "-":
            eprint(f"Instance {selected.instance_id} has no public IP; SSH cannot connect directly.")
            pause()
            return False

        svc.ssh_with_temporary_ingress(selected.instance_id, selected.public_ip)
        pause()
        return False

    if choice == "n":
        maybe_auto_reload_for_action(reload_state, "n", "launch")
        inst_id = svc.launch_instance()
        if prompt_yes_no(
            f"Wait until SSM is Online for {inst_id} and run clawd bootstrap?",
            default_no=True,
        ):
            svc.wait_for_ssm_online(inst_id)
            svc.copy_bootstrap_script_via_ssm(inst_id)
            svc.run_bootstrap_script_via_ssm(inst_id)
        pause()
        return False

    if choice == "b":
        maybe_auto_reload_for_action(reload_state, "b", "bootstrap")
        instances = svc.list_running_instances()
        show_instances(instances)
        if not instances:
            pause()
            return False

        eprint("\nSelect one running instance for bootstrap:")
        selected = choose_single_instance(instances)
        if selected is None:
            pause()
            return False
        if selected.state != "running":
            eprint(f"Instance {selected.instance_id} is '{selected.state}'. It must be running for bootstrap.")
            pause()
            return False

        status = svc.get_ssm_ping_status(selected.instance_id)
        if status != "Online":
            eprint(f"SSM PingStatus is {status or 'Unavailable'} for {selected.instance_id}.")
            if not prompt_yes_no("Wait for SSM to become Online and continue bootstrap?", default_no=True):
                pause()
                return False
            svc.wait_for_ssm_online(selected.instance_id)

        svc.copy_bootstrap_script_via_ssm(selected.instance_id)
        svc.run_bootstrap_script_via_ssm(selected.instance_id)
        pause()
        return False

    if choice == "x":
        maybe_auto_reload_for_action(reload_state, "x", "reset")
        instances = svc.list_running_instances()
        show_instances(instances)
        if instances:
            ids = [i.instance_id for i in instances]
            eprint("\nThis reset will terminate ALL listed instances above.")
            confirm = prompt("Type TERMINATE to confirm: ").strip()
            if confirm != "TERMINATE":
                eprint("Canceled. No instances terminated.")
                pause()
                return False
            svc.terminate_instances(ids)
            eprint("Termination initiated.")
        else:
            eprint("No instances to terminate.")

        if prompt_yes_no("\nLaunch a new instance now?", default_no=True):
            inst_id = svc.launch_instance()
            if prompt_yes_no(
                f"Wait until SSM is Online for {inst_id} and run clawd bootstrap?",
                default_no=True,
            ):
                svc.wait_for_ssm_online(inst_id)
                svc.copy_bootstrap_script_via_ssm(inst_id)
                svc.run_bootstrap_script_via_ssm(inst_id)
        pause()
        return False

    if choice == "r":
        reload_self()

    if choice == "q":
        eprint("Bye.")
        return True

    eprint("Invalid choice.")
    pause()
    return False


def menu_loop(svc: ClawdService) -> None:
    reload_state = snapshot_reload_state(tracked_reload_files())

    while True:
        menu_title()
        eprint("\nChoose an action:")
        eprint("  l) List all instances (all states)")
        eprint("  t) Terminate instances (select)")
        eprint("  s) SSM session to an instance")
        eprint("  h) SSH (temporary ingress from current IP)")
        eprint("  n) Launch new instance (Ubuntu ARM, SSM-ready)")
        eprint("  b) Bootstrap a running instance via SSM")
        eprint("  x) Reset (terminate -> optionally launch)")
        eprint("  r) Reload clawdctl")
        eprint("  q) Exit")

        choice = prompt("\nEnter choice [l/t/s/h/n/b/x/r/q]: ").strip().lower()

        try:
            if run_action(svc, choice, reload_state=reload_state, pause_after=True):
                return

        except KeyboardInterrupt:
            eprint("\nInterrupted. Returning to menu.")
            continue
        except RuntimeError as ex:
            eprint(f"\nAWS error: {ex}")
            prompt("\nPress Enter to continue...")
        except Exception as ex:
            eprint(f"\nUnexpected error: {ex}")
            prompt("\nPress Enter to continue...")


class ClawdArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_help(sys.stderr)
        self.exit(2, f"\nerror: {message}\n")


def main() -> None:
    parser = ClawdArgumentParser(description="clawdctl EC2 lifecycle helper")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (reserved; supports stacking, e.g. -vvv)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="count",
        default=0,
        help="Decrease output verbosity (reserved; supports stacking, e.g. -qq)",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("-l", "--list", action="store_true", help="List all instances (all states)")
    actions.add_argument("-t", "--terminate", action="store_true", help="Terminate instances (select)")
    actions.add_argument("-s", "--ssm", action="store_true", help="Start SSM session to an instance")
    actions.add_argument("-p", "--ssh", action="store_true", help="SSH with temporary ingress from current IP")
    actions.add_argument("-n", "--launch", action="store_true", help="Launch new instance")
    actions.add_argument("-b", "--bootstrap", action="store_true", help="Bootstrap a running instance via SSM")
    actions.add_argument("-x", "--reset", action="store_true", help="Reset (terminate then optionally launch)")
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Start interactive menu loop",
    )
    args = parser.parse_args()
    _ = args.verbose, args.quiet

    require_aws_cli()
    aws = AwsCli(PROFILE, REGION)
    svc = ClawdService(aws)

    action_key: Optional[str] = None
    if args.list:
        action_key = "l"
    elif args.terminate:
        action_key = "t"
    elif args.ssm:
        action_key = "s"
    elif args.ssh:
        action_key = "h"
    elif args.launch:
        action_key = "n"
    elif args.bootstrap:
        action_key = "b"
    elif args.reset:
        action_key = "x"

    if args.interactive or action_key is None:
        menu_loop(svc)
        return

    reload_state = snapshot_reload_state(tracked_reload_files())
    run_action(svc, action_key, reload_state=reload_state, pause_after=False)


if __name__ == "__main__":
    main()
