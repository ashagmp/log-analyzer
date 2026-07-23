from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from datetime import datetime
import io

def generate_report(data):
    """
    Generate a professional PDF threat report from analysis results.
    Supports multi-page output for large alert sets.
    Returns a BytesIO buffer ready for Flask send_file.
    """
    buffer = io.BytesIO()
    width, height = A4
    c = canvas.Canvas(buffer, pagesize=A4)

    report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Severity counts
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in data.get("alerts", []):
        if a["severity"] in sev:
            sev[a["severity"]] += 1

    # Color palette
    BG      = colors.HexColor('#0e0e12')
    SURFACE = colors.HexColor('#16161d')
    PURPLE  = colors.HexColor('#7c3aed')
    LAVENDER= colors.HexColor('#a78bfa')
    DIM     = colors.HexColor('#4b5563')
    BRIGHT  = colors.HexColor('#f9fafb')
    RED     = colors.HexColor('#f87171')
    ORANGE  = colors.HexColor('#fb923c')
    YELLOW  = colors.HexColor('#fbbf24')
    BORDER  = colors.HexColor('#22222e')

    sev_colors = {
        'CRITICAL': '#f87171',
        'HIGH':     '#fb923c',
        'MEDIUM':   '#fbbf24',
        'LOW':      '#34d399',
        'N/A':      '#4b5563'
    }

    def draw_background(c):
        c.setFillColor(BG)
        c.rect(0, 0, width, height, fill=1, stroke=0)
        c.setFillColor(PURPLE)
        c.rect(0, height - 4, width, 4, fill=1, stroke=0)
        c.setFillColor(PURPLE)
        c.setFillAlpha(0.15)
        c.rect(0, 0, 3, height, fill=1, stroke=0)
        c.setFillAlpha(1)

    def draw_header(c):
        c.setFillColor(LAVENDER)
        c.setFont('Helvetica-Bold', 20)
        c.drawString(20*mm, height - 22*mm, 'LOG ANALYZER')
        c.setFillColor(DIM)
        c.setFont('Helvetica', 8)
        c.drawString(20*mm, height - 27*mm, 'SOC INCIDENT DETECTION REPORT')
        c.setFillColor(DIM)
        c.setFont('Helvetica', 8)
        c.drawRightString(width - 20*mm, height - 22*mm, report_date)
        c.setStrokeColor(PURPLE)
        c.setStrokeAlpha(0.3)
        c.setLineWidth(0.5)
        c.line(20*mm, height - 32*mm, width - 20*mm, height - 32*mm)
        c.setStrokeAlpha(1)

    def draw_footer(c, page_num):
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.5)
        c.line(20*mm, 12*mm, width - 20*mm, 12*mm)
        c.setFillColor(DIM)
        c.setFont('Helvetica', 7)
        c.drawString(20*mm, 8*mm, 'LOG ANALYZER — SOC INCIDENT DETECTION')
        c.drawRightString(width - 20*mm, 8*mm, f'PAGE {page_num}')

    def draw_section_label(c, y, text):
        c.setFillColor(DIM)
        c.setFont('Helvetica', 7)
        c.drawString(20*mm, y, text)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.5)
        c.line(20*mm, y - 2*mm, width - 20*mm, y - 2*mm)

    # ── PAGE 1 ──
    draw_background(c)
    draw_header(c)

    y = height - 42*mm

    # Overview stat boxes
    draw_section_label(c, y, 'OVERVIEW')
    y -= 8*mm

    stats = [
        ('LINES PARSED',  str(data.get('total_lines', 0)),   '#a78bfa'),
        ('SKIPPED LINES', str(data.get('skipped_lines', 0)), '#4b5563'),
        ('TOTAL ALERTS',  str(data.get('total_alerts', 0)),  '#a78bfa'),
        ('CRITICAL',      str(sev['CRITICAL']),               '#f87171'),
        ('HIGH',          str(sev['HIGH']),                   '#fb923c'),
        ('BRUTE FORCE',   str(data.get('brute_force_unique_ips', 0)), '#f87171'),
    ]

    box_w = 28*mm
    box_h = 16*mm
    gap   = 3*mm
    total_w = len(stats) * box_w + (len(stats) - 1) * gap
    start_x = (width - total_w) / 2

    for i, (label, value, col) in enumerate(stats):
        bx = start_x + i * (box_w + gap)
        c.setFillColor(SURFACE)
        c.rect(bx, y - box_h, box_w, box_h, fill=1, stroke=0)
        c.setStrokeColor(colors.HexColor(col))
        c.setStrokeAlpha(0.25)
        c.setLineWidth(0.5)
        c.rect(bx, y - box_h, box_w, box_h, fill=0, stroke=1)
        c.setStrokeAlpha(1)
        c.setFillColor(colors.HexColor(col))
        c.rect(bx, y - 1.5, box_w, 1.5, fill=1, stroke=0)
        c.setFillColor(colors.HexColor(col))
        c.setFont('Helvetica-Bold', 16)
        c.drawCentredString(bx + box_w/2, y - box_h/2 - 2, value)
        c.setFillColor(DIM)
        c.setFont('Helvetica', 6)
        c.drawCentredString(bx + box_w/2, y - box_h + 3, label)

    y -= box_h + 10*mm

    # Attack types
    draw_section_label(c, y, 'ATTACK TYPES DETECTED')
    y -= 8*mm

    attack_counts = data.get('attack_counts', {})
    if attack_counts:
        max_count = max(attack_counts.values(), default=1)
        bar_width = width - 80*mm
        for name, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            c.setFillColor(DIM)
            c.setFont('Helvetica', 8)
            c.drawString(20*mm, y, name)
            track_x = 65*mm
            c.setFillColor(BORDER)
            c.rect(track_x, y - 1, bar_width, 4, fill=1, stroke=0)
            c.setFillColor(RED)
            c.rect(track_x, y - 1, (count / max_count) * bar_width, 4, fill=1, stroke=0)
            c.setFillColor(DIM)
            c.setFont('Helvetica', 7)
            c.drawString(track_x + bar_width + 3*mm, y, str(count))
            y -= 8*mm
    else:
        c.setFillColor(DIM)
        c.setFont('Helvetica', 8)
        c.drawString(20*mm, y, 'No attacks detected')
        y -= 8*mm

    y -= 4*mm

    # Brute force
    draw_section_label(c, y, 'PERSISTENT BRUTE FORCE (10+ FAILED ATTEMPTS)')
    y -= 8*mm

    brute_force = data.get('brute_force', [])
    if brute_force:
        for bf in brute_force:
            c.setFillColor(SURFACE)
            c.rect(20*mm, y - 10*mm, width - 40*mm, 10*mm, fill=1, stroke=0)
            c.setStrokeColor(RED)
            c.setStrokeAlpha(0.15)
            c.setLineWidth(0.5)
            c.rect(20*mm, y - 10*mm, width - 40*mm, 10*mm, fill=0, stroke=1)
            c.setStrokeAlpha(1)
            c.setFillColor(RED)
            c.setFont('Helvetica-Bold', 9)
            c.drawString(23*mm, y - 6*mm, bf['ip'])
            c.setFillColor(DIM)
            c.setFont('Helvetica', 8)
            c.drawString(70*mm, y - 6*mm, f"{bf['attempts']} failed attempts · {bf['tactic']}")
            c.setFillColor(LAVENDER)
            c.setFont('Helvetica', 7)
            c.drawRightString(width - 23*mm, y - 6*mm, bf['mitre'])
            y -= 12*mm
    else:
        c.setFillColor(DIM)
        c.setFont('Helvetica', 8)
        c.drawString(20*mm, y - 6*mm, 'No persistent brute force detected')
        y -= 12*mm

    y -= 4*mm

    # Alerts table
    draw_section_label(c, y, 'SECURITY ALERTS')
    y -= 8*mm

    col_widths  = [38*mm, 28*mm, 45*mm, 26*mm, 16*mm, 17*mm]
    headers     = ['TIME', 'IP', 'PATH', 'ATTACK', 'MITRE', 'SEVERITY']
    x_positions = [20*mm]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)

    def draw_table_header(c, y):
        c.setFillColor(SURFACE)
        c.rect(20*mm, y - 6*mm, width - 40*mm, 6*mm, fill=1, stroke=0)
        c.setFillColor(DIM)
        c.setFont('Helvetica-Bold', 7)
        for i, header in enumerate(headers):
            c.drawString(x_positions[i] + 1*mm, y - 4*mm, header)
        return y - 6*mm

    y = draw_table_header(c, y)

    page_num = 1
    alerts   = data.get('alerts', [])

    for idx, alert in enumerate(alerts[:500]):
        if y - 8*mm < 20*mm:
            draw_footer(c, page_num)
            c.showPage()
            page_num += 1
            draw_background(c)
            draw_header(c)
            y = height - 42*mm
            draw_section_label(c, y, 'SECURITY ALERTS (CONTINUED)')
            y -= 8*mm
            y = draw_table_header(c, y)

        bg = '#16161d' if idx % 2 == 0 else '#0e0e12'
        c.setFillColor(colors.HexColor(bg))
        c.rect(20*mm, y - 8*mm, width - 40*mm, 8*mm, fill=1, stroke=0)

        c.setFillColor(DIM)
        c.setFont('Helvetica', 6.5)
        c.drawString(x_positions[0] + 1*mm, y - 5*mm, str(alert['time'])[:20])

        c.setFillColor(LAVENDER)
        c.setFont('Helvetica', 6.5)
        c.drawString(x_positions[1] + 1*mm, y - 5*mm, str(alert['ip']))

        path = str(alert['path'])
        path = path[:35] + '...' if len(path) > 35 else path
        c.setFillColor(RED)
        c.setFont('Helvetica', 6.5)
        c.drawString(x_positions[2] + 1*mm, y - 5*mm, path)

        c.setFillColor(BRIGHT)
        c.setFont('Helvetica', 6.5)
        c.drawString(x_positions[3] + 1*mm, y - 5*mm, str(alert['name']))

        c.setFillColor(LAVENDER)
        c.setFont('Helvetica', 6.5)
        c.drawString(x_positions[4] + 1*mm, y - 5*mm, str(alert['mitre']))

        sev_col = sev_colors.get(alert['severity'], '#4b5563')
        c.setFillColor(colors.HexColor(sev_col))
        c.setFont('Helvetica-Bold', 6.5)
        c.drawString(x_positions[5] + 1*mm, y - 5*mm, str(alert['severity']))

        y -= 8*mm

    draw_footer(c, page_num)
    c.save()
    buffer.seek(0)
    return buffer
