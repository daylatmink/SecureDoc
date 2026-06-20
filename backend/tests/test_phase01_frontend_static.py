from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAIN_TSX = REPO_ROOT / "frontend" / "src" / "main.tsx"
SIGNING_CLIENT = REPO_ROOT / "frontend" / "src" / "signing-v2.ts"


def test_documents_workflow_is_not_in_sidebar():
    source = MAIN_TSX.read_text(encoding="utf-8")

    assert "DocumentsWorkflow" not in source
    assert 'tab: "documents"' not in source
    assert "Main flow" not in source


def test_user_flow_has_no_ca_or_auditor_auto_login():
    source = SIGNING_CLIENT.read_text(encoding="utf-8") + MAIN_TSX.read_text(encoding="utf-8")

    assert "/api/auth/demo-login" not in source
    assert "demoLogin" not in source
    assert 'roleAuthHeaders("CA_OFFICER")' not in source
    assert 'roleAuthHeaders("AUDITOR")' not in source
