import io
import json
import os
import logging
_logger = logging.getLogger()
##
try:
    import qrcode
    has_qrcode = True
    _logger.warning(('Could not import qrcode; '
                     'library required for QR code generation'))
except ImportError:
    has_qrcode = False
try:
    import qrcode.image.svg
    has_qrcode_svg = True
except ImportError:
    has_qrcode_svg = False
    _logger.error(('Could not import qrcode.image.svg; '
                   'library required for image QR code generation'))


def genQr(data, image = False):
    if isinstance(data, dict):
        data = json.dumps(dict, indent = 4)
    if not isinstance(data, str):
        data = str(data)
    _logger.debug('Generating QR code')
    qr = qrcode.QRCode(error_correction = qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(data)
    qr.make(fit = True)
    termname = os.environ.get('TERM', 'linux')
    if termname == 'linux':
        # We can't spawn an xdg-open because we don't have X.
        _logger.warning('Disabling image display/generation because we don\'t have X')
        image = False
    if not image:
        _logger.debug('Rendering to terminal')
        buf = io.StringIO()
        if termname == 'linux' or termname.startswith('screen'):
            invert = False
        else:
            _logger.debug('Inverting B/W for better visibility in environment (we cannot predict terminal colours)')
            invert = True
        qr.print_ascii(invert = invert, out = buf)
    else:
        _logger.debug('Rendering to image')
        buf = io.BytesIO()
        if not has_qrcode_svg:
            _logger.warning('Falling back to PNG for image generation; could not support SVG')
            # Generate a PNG
            img = qr.make_image()
        else:
            _logger.debug('Generating an SVG')
            # Preferred; generate an SVG.
            factory = qrcode.image.svg.SvgPathFillImage
            img = qrcode.make(data, image_factory = factory)
        img.save(buf)
    buf.seek(0, 0)
    return(buf, image)
