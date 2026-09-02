"""Wave 18.6 T2 - every setting app/config.py reads must reach the container.

WHAT WENT WRONG: `app/config.py` reads `EMAIL_INTAKE_SECRETS` from the environment and
`app/routers/diagnostics.py::_require_email_auth` returns 503 "email intake is not
configured" when it is empty. `docker-compose.yml` never passed the variable into the
container, so on the deployed box the setting was permanently empty and
`POST /api/v1/diagnostics/email` answered 503 forever - no matter what `.env` said.
Setting it "correctly" produced no change and no error message, which is the worst shape
a configuration bug can take.

It was not alone. An audit on 2026-08-30 found FIVE settings in this state:
EMAIL_INTAKE_SECRETS, WEB_INTAKE_CORS_ORIGINS, LICENSE_VERIFY_RATE_PER_MIN,
MAX_REQUEST_BODY_BYTES and OBJECT_STORE_URL.

So the test is the general rule, not the one variable: anything `config.py` reads from
the environment must appear in the compose `environment:` list. Adding a new setting to
`config.py` without a compose line now fails here instead of shipping as a silently
ignored knob.
"""
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PY = os.path.join(REPO_ROOT, "app", "config.py")
COMPOSE_YML = os.path.join(REPO_ROOT, "docker-compose.yml")

# Settings that are deliberately NOT passed through, with the reason. Empty today. A new
# entry here needs a real justification in review - the default answer is "add the
# compose line", not "add an exemption".
INTENTIONALLY_NOT_PASSED: dict[str, str] = {}


def _env_names_read_by_config() -> set[str]:
    src = open(CONFIG_PY, encoding="utf-8").read()
    # os.environ.get("NAME"...) - the name may sit on the next line when the call is
    # wrapped, so allow whitespace/newlines between the paren and the literal.
    return set(re.findall(r'os\.environ(?:\.get)?[\(\[]\s*"([A-Z0-9_]+)"', src))


def _env_names_passed_by_compose() -> set[str]:
    src = open(COMPOSE_YML, encoding="utf-8").read()
    return set(re.findall(r"^\s*-\s*([A-Z0-9_]+)=", src, re.MULTILINE))


def test_config_reads_at_least_the_known_settings():
    """Guards the regexes above: if `config.py` is refactored into a style these
    patterns no longer match, this test fails loudly instead of the parity test below
    quietly passing on an empty set."""
    read = _env_names_read_by_config()
    assert len(read) >= 15, f"only found {len(read)} env reads in config.py - regex stale?"
    for expected in ("EMAIL_INTAKE_SECRETS", "ADMIN_API_TOKENS", "DATABASE_URL"):
        assert expected in read, f"{expected} not detected in config.py"


def test_every_setting_config_reads_is_passed_through_by_compose():
    read = _env_names_read_by_config()
    passed = _env_names_passed_by_compose()
    missing = sorted(read - passed - set(INTENTIONALLY_NOT_PASSED))
    assert not missing, (
        "app/config.py reads these from the environment but docker-compose.yml never "
        f"passes them into the container, so setting them in .env does nothing: {missing}"
    )


@pytest.mark.parametrize(
    "name",
    [
        "EMAIL_INTAKE_SECRETS",
        "WEB_INTAKE_CORS_ORIGINS",
        "LICENSE_VERIFY_RATE_PER_MIN",
        "MAX_REQUEST_BODY_BYTES",
        "OBJECT_STORE_URL",
    ],
)
def test_the_five_that_were_missing_are_now_passed(name):
    """Named individually so a regression on any one of them reads as itself."""
    assert name in _env_names_passed_by_compose(), (
        f"{name} is read by app/config.py but missing from docker-compose.yml"
    )


def test_email_intake_secrets_is_not_made_mandatory():
    """`EMAIL_INTAKE_SECRETS` must NOT use compose's `:?` required-variable form.

    Email intake is optional and fail-closed by design: with no secret the route answers
    503 and the rest of the service runs normally. Marking it required would make
    `docker compose up` refuse to start the whole support service on a box that simply
    does not do email intake.
    """
    src = open(COMPOSE_YML, encoding="utf-8").read()
    line = next(l for l in src.splitlines() if "EMAIL_INTAKE_SECRETS=" in l)
    assert ":?" not in line, f"EMAIL_INTAKE_SECRETS must stay optional, got: {line.strip()}"
