import configparser
import copy
import pickle
from pathlib import Path

import cowrie
import pytest
from cowrie.shell import honeyfs

from vulnmaze.cowrie_ext.hooks import add_files
from vulnmaze.llm.persona import Persona
from vulnmaze.llm.pinning import PersonaChecker, fact_contradictions
from vulnmaze.router.known_commands import KNOWN_COMMANDS

ROOT = Path(__file__).resolve().parents[2]
STOCK = pickle.loads((Path(cowrie.__file__).parent / "data/fs.pickle").read_bytes())


def test_persona_matches_cowrie_config(persona):
    """The LLM persona and Cowrie's own config describe the same machine."""
    cfg = configparser.RawConfigParser()
    cfg.read(ROOT / "infra/honeypot/cowrie.cfg")
    assert cfg["honeypot"]["hostname"] == persona.hostname
    assert cfg["shell"]["kernel_version"] == persona.kernel
    assert persona.codename in persona.os_pretty
    assert "Debian" in cfg["shell"]["kernel_build_string"] and persona.os_id == "debian"


def test_openssl_version_matches_cowrie_banner(persona):
    """The SSH banner Cowrie sends advertises the OpenSSL version the persona claims."""
    cfg = configparser.RawConfigParser()
    cfg.read(ROOT / "infra/honeypot/cowrie.cfg")
    assert f"OpenSSL {persona.facts['openssl_version']}" in cfg["shell"]["ssh_version"]


def test_command_lists_do_not_overlap_cowrie_commands(persona):
    """Cowrie implements KNOWN_COMMANDS itself, so the persona must not claim them
    installed (redundant) or absent (a contradiction Cowrie would expose)."""
    assert not (persona.absent & KNOWN_COMMANDS)
    assert not (persona.installed & KNOWN_COMMANDS), sorted(persona.installed & KNOWN_COMMANDS)


def test_persona_rejects_overlapping_command_lists(tmp_path):
    """A command cannot be both installed and absent."""
    raw = (ROOT / "infra/persona/persona.yml").read_text().replace("    - masscan", "    - masscan\n    - lsblk")  # also "ss"
    path = tmp_path / "persona.yml"
    path.write_text(raw)
    with pytest.raises(ValueError):
        Persona.load(path)


def test_checker_accepts_consistent_output(persona):
    """Output that repeats persona facts passes."""
    text = f"Linux {persona.hostname} {persona.kernel} #1 SMP\ninet {persona.facts['primary_ip']}/24\nnginx/1.22.1"
    assert PersonaChecker(persona).check(text) == []


@pytest.mark.parametrize("text,reason", [
    ("Linux mailhost 6.1.0-21-amd64 #1", "contradicts_persona:hostname=mailhost"),
    ("Ubuntu 22.04.3 LTS", "contradicts_persona:os=Ubuntu"),
    ("VERSION_CODENAME=jammy", "contradicts_persona:codename=jammy"),
    ("6.8.0-45-generic", "contradicts_persona:kernel=6.8.0-45-generic"),
    ("inet 192.168.1.50/24", "contradicts_persona:ip=192.168.1.50"),
    ("Server: nginx/1.18.0", "contradicts_persona:nginx_version=1.18.0"),
])
def test_checker_catches_contradictions(persona, text, reason):
    """Each kind of persona contradiction is detected without a model."""
    assert reason in PersonaChecker(persona).check(text)


def test_declared_and_stored_fact_contradictions(persona):
    """Declared facts must agree with the persona and with facts already pinned."""
    assert PersonaChecker(persona).check_declared({"php_version": "7.4.0"}) == ["contradicts_persona:php_version=7.4.0"]
    assert fact_contradictions({"db": "a", "new": "x"}, {"db": "b"}) == ["contradicts_fact:db"]


def test_persona_filesystem_gives_cowrie_the_web_server_it_describes(persona):
    """On Cowrie's stock filesystem the persona adds its web root and server configs, keeps every stock entry, and leaves the bait paths free."""
    tree = copy.deepcopy(STOCK)
    add_files(tree, persona.filesystem)
    web_root = honeyfs._find(tree, persona.facts["web_root"])
    assert web_root[1] == 1 and web_root[6] == honeyfs._find(STOCK, "/var")[6]
    assert b"root /var/www/portal/public;" in honeyfs._find(tree, "/etc/nginx/sites-enabled/portal")[7]
    assert honeyfs._find(tree, "/etc/passwd")[7] == honeyfs._find(STOCK, "/etc/passwd")[7]
    assert honeyfs._find(tree, "/var/www/portal/config/database.php") is None


@pytest.mark.parametrize("files", [{"/etc/passwd": "x"}, {"/etc/passwd/x": "y"}, {}])
def test_persona_filesystem_never_replaces_or_breaks_stock_entries(files):
    """An existing file is not overwritten, a path below a file is skipped, and nothing is added for an empty list."""
    tree = copy.deepcopy(STOCK)
    add_files(tree, files)
    assert tree == STOCK
