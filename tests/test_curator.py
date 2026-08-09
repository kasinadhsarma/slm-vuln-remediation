from slm_avr.agents.curator import CuratorAgent


def test_gather_finds_callers_and_related_definitions(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "config.py").write_text('BACKUP_ROOT = "/var/backups"\n')
    (pkg / "vuln.py").write_text(
        "import os\n"
        "from pkg.config import BACKUP_ROOT\n\n"
        "def run_backup(target_dir):\n"
        '    os.system("tar -czf backup.tar.gz " + target_dir)\n'
    )
    (pkg / "caller.py").write_text(
        "from pkg.vuln import run_backup\n\n"
        "def scheduled_job():\n"
        '    run_backup("/data/uploads")\n'
    )

    curator = CuratorAgent(str(tmp_path))
    ctx = curator.gather(
        str(pkg / "vuln.py"), "run_backup", {"BACKUP_ROOT", "os"}
    )

    assert any("caller.py" in c and "run_backup" in c for c in ctx.callers)
    assert any("BACKUP_ROOT" in d and "config.py" in d for d in ctx.related_definitions)
    assert any("caller.py" in m for m in ctx.imported_by)
