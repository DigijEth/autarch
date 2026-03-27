"""Container Security routes."""

from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

container_sec_bp = Blueprint('container_sec', __name__, url_prefix='/container-sec')


def _get_cs():
    from modules.container_sec import get_container_sec
    return get_container_sec()


# ── Pages ────────────────────────────────────────────────────────────────────

@container_sec_bp.route('/')
@login_required
def index():
    return render_template('container_sec.html')


# ── Status ───────────────────────────────────────────────────────────────────

@container_sec_bp.route('/status')
@login_required
def status():
    """Check Docker and kubectl availability."""
    cs = _get_cs()
    return jsonify({
        'docker': cs.check_docker_installed(),
        'kubectl': cs.check_kubectl_installed(),
    })


# ── Docker: Host Audit ──────────────────────────────────────────────────────

@container_sec_bp.route('/docker/audit', methods=['POST'])
@login_required
def docker_audit():
    """Audit Docker host configuration."""
    findings = _get_cs().audit_docker_host()
    return jsonify({'findings': findings, 'total': len(findings)})


# ── Docker: Containers ──────────────────────────────────────────────────────

@container_sec_bp.route('/docker/containers')
@login_required
def docker_containers():
    """List Docker containers."""
    containers = _get_cs().list_containers(all=True)
    return jsonify({'containers': containers, 'total': len(containers)})


@container_sec_bp.route('/docker/containers/<container_id>/audit', methods=['POST'])
@login_required
def docker_container_audit(container_id):
    """Audit a specific container."""
    result = _get_cs().audit_container(container_id)
    return jsonify(result)


@container_sec_bp.route('/docker/containers/<container_id>/escape', methods=['POST'])
@login_required
def docker_container_escape(container_id):
    """Check container escape vectors."""
    result = _get_cs().check_escape_vectors(container_id)
    return jsonify(result)


# ── Docker: Images ───────────────────────────────────────────────────────────

@container_sec_bp.route('/docker/images')
@login_required
def docker_images():
    """List local Docker images."""
    images = _get_cs().list_images()
    return jsonify({'images': images, 'total': len(images)})


@container_sec_bp.route('/docker/images/scan', methods=['POST'])
@login_required
def docker_image_scan():
    """Scan a Docker image for vulnerabilities."""
    data = request.get_json(silent=True) or {}
    image_name = data.get('image_name', '').strip()
    if not image_name:
        return jsonify({'error': 'No image name provided'}), 400
    result = _get_cs().scan_image(image_name)
    return jsonify(result)


# ── Dockerfile Lint ──────────────────────────────────────────────────────────

@container_sec_bp.route('/docker/lint', methods=['POST'])
@login_required
def docker_lint():
    """Lint Dockerfile content for security issues."""
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    if not content.strip():
        return jsonify({'error': 'No Dockerfile content provided'}), 400
    findings = _get_cs().lint_dockerfile(content)
    return jsonify({'findings': findings, 'total': len(findings)})


# ── Kubernetes: Namespaces & Pods ────────────────────────────────────────────

@container_sec_bp.route('/k8s/namespaces')
@login_required
def k8s_namespaces():
    """List Kubernetes namespaces."""
    namespaces = _get_cs().k8s_get_namespaces()
    return jsonify({'namespaces': namespaces, 'total': len(namespaces)})


@container_sec_bp.route('/k8s/pods')
@login_required
def k8s_pods():
    """List pods in a namespace."""
    namespace = request.args.get('namespace', 'default')
    pods = _get_cs().k8s_get_pods(namespace=namespace)
    return jsonify({'pods': pods, 'total': len(pods)})


@container_sec_bp.route('/k8s/pods/<name>/audit', methods=['POST'])
@login_required
def k8s_pod_audit(name):
    """Audit a specific pod."""
    data = request.get_json(silent=True) or {}
    namespace = data.get('namespace', 'default')
    result = _get_cs().k8s_audit_pod(name, namespace=namespace)
    return jsonify(result)


# ── Kubernetes: RBAC, Secrets, Network Policies ──────────────────────────────

@container_sec_bp.route('/k8s/rbac', methods=['POST'])
@login_required
def k8s_rbac():
    """Audit RBAC configuration."""
    data = request.get_json(silent=True) or {}
    namespace = data.get('namespace') or None
    result = _get_cs().k8s_audit_rbac(namespace=namespace)
    return jsonify(result)


@container_sec_bp.route('/k8s/secrets', methods=['POST'])
@login_required
def k8s_secrets():
    """Check secrets exposure."""
    data = request.get_json(silent=True) or {}
    namespace = data.get('namespace', 'default')
    result = _get_cs().k8s_check_secrets(namespace=namespace)
    return jsonify(result)


@container_sec_bp.route('/k8s/network', methods=['POST'])
@login_required
def k8s_network():
    """Check network policies."""
    data = request.get_json(silent=True) or {}
    namespace = data.get('namespace', 'default')
    result = _get_cs().k8s_check_network_policies(namespace=namespace)
    return jsonify(result)


# ── Export ───────────────────────────────────────────────────────────────────

@container_sec_bp.route('/export')
@login_required
def export():
    """Export all audit results."""
    fmt = request.args.get('format', 'json')
    result = _get_cs().export_results(fmt=fmt)
    return jsonify(result)
