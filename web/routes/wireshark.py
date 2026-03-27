"""Wireshark/Packet Analysis route - capture, PCAP analysis, protocol/DNS/HTTP/credential analysis."""

import json
from pathlib import Path
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from web.auth import login_required

wireshark_bp = Blueprint('wireshark', __name__, url_prefix='/wireshark')


@wireshark_bp.route('/')
@login_required
def index():
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    status = mgr.get_status()
    return render_template('wireshark.html', status=status)


@wireshark_bp.route('/status')
@login_required
def status():
    """Get engine status."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify(mgr.get_status())


@wireshark_bp.route('/interfaces')
@login_required
def interfaces():
    """List network interfaces."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify({'interfaces': mgr.list_interfaces()})


@wireshark_bp.route('/capture/start', methods=['POST'])
@login_required
def capture_start():
    """Start packet capture."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()

    data = request.get_json(silent=True) or {}
    interface = data.get('interface', '').strip() or None
    bpf_filter = data.get('filter', '').strip() or None
    duration = int(data.get('duration', 30))

    result = mgr.start_capture(
        interface=interface,
        bpf_filter=bpf_filter,
        duration=duration,
    )
    return jsonify(result)


@wireshark_bp.route('/capture/stop', methods=['POST'])
@login_required
def capture_stop():
    """Stop running capture."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify(mgr.stop_capture())


@wireshark_bp.route('/capture/stats')
@login_required
def capture_stats():
    """Get capture statistics."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify(mgr.get_capture_stats())


@wireshark_bp.route('/capture/stream')
@login_required
def capture_stream():
    """SSE stream of live capture packets."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()

    def generate():
        import time
        last_count = 0
        while mgr._capture_running:
            stats = mgr.get_capture_stats()
            count = stats.get('packet_count', 0)

            if count > last_count:
                # Send new packets
                new_packets = mgr._capture_packets[last_count:count]
                for pkt in new_packets:
                    yield f'data: {json.dumps({"type": "packet", **pkt})}\n\n'
                last_count = count

            yield f'data: {json.dumps({"type": "stats", "packet_count": count, "running": True})}\n\n'
            time.sleep(0.5)

        # Final stats
        stats = mgr.get_capture_stats()
        yield f'data: {json.dumps({"type": "done", **stats})}\n\n'

    return Response(stream_with_context(generate()), content_type='text/event-stream')


@wireshark_bp.route('/pcap/analyze', methods=['POST'])
@login_required
def analyze_pcap():
    """Analyze a PCAP file (by filepath)."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()

    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()
    max_packets = int(data.get('max_packets', 5000))

    if not filepath:
        return jsonify({'error': 'No filepath provided'})

    p = Path(filepath)
    if not p.exists():
        return jsonify({'error': f'File not found: {filepath}'})
    if not p.suffix.lower() in ('.pcap', '.pcapng', '.cap'):
        return jsonify({'error': 'File must be .pcap, .pcapng, or .cap'})

    result = mgr.read_pcap(filepath, max_packets=max_packets)

    # Limit packet list sent to browser
    if 'packets' in result and len(result['packets']) > 500:
        result['packets'] = result['packets'][:500]
        result['truncated'] = True

    return jsonify(result)


@wireshark_bp.route('/analyze/protocols', methods=['POST'])
@login_required
def analyze_protocols():
    """Get protocol hierarchy from loaded packets."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify(mgr.get_protocol_hierarchy())


@wireshark_bp.route('/analyze/conversations', methods=['POST'])
@login_required
def analyze_conversations():
    """Get IP conversations."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify({'conversations': mgr.extract_conversations()})


@wireshark_bp.route('/analyze/dns', methods=['POST'])
@login_required
def analyze_dns():
    """Get DNS queries."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify({'queries': mgr.extract_dns_queries()})


@wireshark_bp.route('/analyze/http', methods=['POST'])
@login_required
def analyze_http():
    """Get HTTP requests."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify({'requests': mgr.extract_http_requests()})


@wireshark_bp.route('/analyze/credentials', methods=['POST'])
@login_required
def analyze_credentials():
    """Detect plaintext credentials."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()
    return jsonify({'credentials': mgr.extract_credentials()})


@wireshark_bp.route('/export', methods=['POST'])
@login_required
def export():
    """Export packets."""
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()

    data = request.get_json(silent=True) or {}
    fmt = data.get('format', 'json')

    result = mgr.export_packets(fmt=fmt)
    return jsonify(result)
