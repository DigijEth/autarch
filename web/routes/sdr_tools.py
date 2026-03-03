"""SDR/RF Tools routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

sdr_tools_bp = Blueprint('sdr_tools', __name__, url_prefix='/sdr-tools')


def _get_sdr():
    from modules.sdr_tools import get_sdr_tools
    return get_sdr_tools()


@sdr_tools_bp.route('/')
@login_required
def index():
    return render_template('sdr_tools.html')


@sdr_tools_bp.route('/devices')
@login_required
def devices():
    return jsonify({'devices': _get_sdr().detect_devices()})


@sdr_tools_bp.route('/spectrum', methods=['POST'])
@login_required
def spectrum():
    data = request.get_json(silent=True) or {}
    freq_start = int(data.get('freq_start', 88000000))
    freq_end = int(data.get('freq_end', 108000000))
    step = int(data['step']) if data.get('step') else None
    gain = int(data['gain']) if data.get('gain') else None
    duration = int(data.get('duration', 5))
    device = data.get('device', 'rtl')
    result = _get_sdr().scan_spectrum(
        device=device, freq_start=freq_start, freq_end=freq_end,
        step=step, gain=gain, duration=duration
    )
    return jsonify(result)


@sdr_tools_bp.route('/capture/start', methods=['POST'])
@login_required
def capture_start():
    data = request.get_json(silent=True) or {}
    result = _get_sdr().start_capture(
        device=data.get('device', 'rtl'),
        frequency=int(data.get('frequency', 100000000)),
        sample_rate=int(data.get('sample_rate', 2048000)),
        gain=data.get('gain', 'auto'),
        duration=int(data.get('duration', 10)),
        output=data.get('output'),
    )
    return jsonify(result)


@sdr_tools_bp.route('/capture/stop', methods=['POST'])
@login_required
def capture_stop():
    return jsonify(_get_sdr().stop_capture())


@sdr_tools_bp.route('/recordings')
@login_required
def recordings():
    return jsonify({'recordings': _get_sdr().list_recordings()})


@sdr_tools_bp.route('/recordings/<rec_id>', methods=['DELETE'])
@login_required
def recording_delete(rec_id):
    return jsonify(_get_sdr().delete_recording(rec_id))


@sdr_tools_bp.route('/replay', methods=['POST'])
@login_required
def replay():
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '')
    frequency = int(data.get('frequency', 100000000))
    sample_rate = int(data.get('sample_rate', 2048000))
    gain = int(data.get('gain', 47))
    return jsonify(_get_sdr().replay_signal(file_path, frequency, sample_rate, gain))


@sdr_tools_bp.route('/demod/fm', methods=['POST'])
@login_required
def demod_fm():
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '')
    frequency = int(data['frequency']) if data.get('frequency') else None
    return jsonify(_get_sdr().demodulate_fm(file_path, frequency))


@sdr_tools_bp.route('/demod/am', methods=['POST'])
@login_required
def demod_am():
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '')
    frequency = int(data['frequency']) if data.get('frequency') else None
    return jsonify(_get_sdr().demodulate_am(file_path, frequency))


@sdr_tools_bp.route('/adsb/start', methods=['POST'])
@login_required
def adsb_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_sdr().start_adsb(device=data.get('device', 'rtl')))


@sdr_tools_bp.route('/adsb/stop', methods=['POST'])
@login_required
def adsb_stop():
    return jsonify(_get_sdr().stop_adsb())


@sdr_tools_bp.route('/adsb/aircraft')
@login_required
def adsb_aircraft():
    return jsonify({'aircraft': _get_sdr().get_adsb_aircraft()})


@sdr_tools_bp.route('/gps/detect', methods=['POST'])
@login_required
def gps_detect():
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 30))
    return jsonify(_get_sdr().detect_gps_spoofing(duration))


@sdr_tools_bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '')
    return jsonify(_get_sdr().analyze_signal(file_path))


@sdr_tools_bp.route('/frequencies')
@login_required
def frequencies():
    return jsonify(_get_sdr().get_common_frequencies())


@sdr_tools_bp.route('/status')
@login_required
def status():
    return jsonify(_get_sdr().get_status())


# ── Drone Detection Routes ──────────────────────────────────────────────────

@sdr_tools_bp.route('/drone/start', methods=['POST'])
@login_required
def drone_start():
    data = request.get_json(silent=True) or {}
    result = _get_sdr().start_drone_detection(data.get('device', 'rtl'), data.get('duration', 0))
    return jsonify(result)


@sdr_tools_bp.route('/drone/stop', methods=['POST'])
@login_required
def drone_stop():
    return jsonify(_get_sdr().stop_drone_detection())


@sdr_tools_bp.route('/drone/detections')
@login_required
def drone_detections():
    return jsonify({'detections': _get_sdr().get_drone_detections()})


@sdr_tools_bp.route('/drone/clear', methods=['DELETE'])
@login_required
def drone_clear():
    _get_sdr().clear_drone_detections()
    return jsonify({'ok': True})


@sdr_tools_bp.route('/drone/status')
@login_required
def drone_status():
    return jsonify({'detecting': _get_sdr().is_drone_detecting(), 'count': len(_get_sdr().get_drone_detections())})
