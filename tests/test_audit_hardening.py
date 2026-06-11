"""Regression tests for audit-hardening fixes that don't fit an existing file."""

from types import SimpleNamespace

from brig.cell.validators import _v_env, _v_workdir
from brig.config import mount_root_slug


class TestEnvNameValidation:
    """The proxy-override guard (reconciler) compares exact env names, so a
    whitespace-padded / non-POSIX key must be rejected at validation time and
    can't smuggle a ` http_proxy` past the egress choke point."""

    def test_whitespace_padded_key_rejected_list(self):
        assert _v_env([" http_proxy=http://evil:8080"], "")  # non-empty = errors

    def test_whitespace_padded_key_rejected_dict(self):
        assert _v_env({" http_proxy": "x"}, "")

    def test_non_posix_key_rejected(self):
        assert _v_env(["FOO-BAR=x"], "")

    def test_normal_names_accepted(self):
        assert not _v_env(["HTTP_PROXY=ok", "FOO=bar", "_X1=y"], "")
        assert not _v_env({"APP_ENV": "prod"}, "")


class TestMountSlugCanonical:
    """mount_root_slug must derive from the realpath so validation's collision
    check and the emitted /mnt/host/<slug> agree — otherwise two symlinked roots
    could collide at one mountPoint with no validation error."""

    def test_slug_resolves_symlink_to_target_basename(self, tmp_path):
        target = tmp_path / "realname"
        target.mkdir()
        link = tmp_path / "alias"
        link.symlink_to(target)
        assert mount_root_slug(str(link)) == "realname"

    def test_two_symlinks_to_same_target_share_slug(self, tmp_path):
        target = tmp_path / "shared"
        target.mkdir()
        (tmp_path / "a").symlink_to(target)
        (tmp_path / "b").symlink_to(target)
        assert mount_root_slug(str(tmp_path / "a")) == mount_root_slug(str(tmp_path / "b"))


class TestWorkdirValidation:
    """--workdir should reject traversal/non-normalized values for consistency
    with the other in-cell path validators."""

    def test_rejects_traversal(self):
        assert _v_workdir("/app/../etc", "")

    def test_rejects_dot_segment(self):
        assert _v_workdir("/app/./x", "")

    def test_rejects_doubled_slash(self):
        assert _v_workdir("/app//x", "")

    def test_accepts_normal(self):
        assert not _v_workdir("/app", "")
        assert not _v_workdir("/work/sub", "")
        assert not _v_workdir(None, "")


class TestReclaimOrphanSubnets:
    """`brig system down` frees subnets whose podman network is gone, but must
    fail safe (free nothing) if the network list can't be read."""

    def test_frees_only_networkless(self, monkeypatch):
        from brig.network import subnet
        monkeypatch.setattr(
            "brig.vm.shell.vm_run",
            lambda cmd, **k: SimpleNamespace(returncode=0, stdout="brig-alive\nwarden\n"),
        )
        monkeypatch.setattr(subnet, "list_all", lambda *a, **k: [
            SimpleNamespace(cell_name="alive", subnet="10.60.1.0/24"),
            SimpleNamespace(cell_name="dead", subnet="10.60.2.0/24"),
        ])
        freed: list[str] = []
        monkeypatch.setattr(subnet, "free", lambda name, *a, **k: freed.append(name))
        assert subnet.reclaim_orphan_subnets() == ["dead"]
        assert freed == ["dead"]

    def test_fails_safe_on_enumeration_error(self, monkeypatch):
        from brig.network import subnet
        monkeypatch.setattr(
            "brig.vm.shell.vm_run",
            lambda cmd, **k: SimpleNamespace(returncode=1, stdout=""),
        )
        freed: list[str] = []
        monkeypatch.setattr(subnet, "free", lambda name, *a, **k: freed.append(name))
        monkeypatch.setattr(subnet, "list_all", lambda *a, **k: [
            SimpleNamespace(cell_name="x", subnet="10.60.1.0/24"),
        ])
        assert subnet.reclaim_orphan_subnets() == []
        assert freed == []
