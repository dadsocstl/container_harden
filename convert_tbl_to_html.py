#!/usr/bin/env python3
"""Convert Trivy TBL format to HTML"""
import sys
import html

def convert_tbl_to_html(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write('<!DOCTYPE html>\n')
        out.write('<html><head><title>Trivy TBL Report</title>\n')
        out.write('<style>\n')
        out.write('table { border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; margin: 20px 0; }\n')
        out.write('th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n')
        out.write('th { background-color: #f2f2f2; font-weight: bold; }\n')
        out.write('tr:nth-child(even) { background-color: #f9f9f9; }\n')
        out.write('tr:hover { background-color: #f5f5f5; }\n')
        out.write('h2 { font-family: Arial, sans-serif; color: #333; }\n')
        out.write('pre { font-family: monospace; background: #f5f5f5; padding: 10px; border: 1px solid #ddd; }\n')
        out.write('</style></head><body><h2>Trivy Scan Report</h2>\n')
        
        in_table = False
        for line in lines:
            line = line.rstrip()
            if line.startswith('┌') or line.startswith('├') or line.startswith('└'):
                continue
            elif '│' in line:
                if not in_table:
                    out.write('<table>\n')
                    in_table = True
                cells = [html.escape(c.strip()) for c in line.split('│')[1:-1]]
                out.write('<tr>')
                for cell in cells:
                    out.write(f'<td>{cell}</td>')
                out.write('</tr>\n')
            elif not line.strip():
                if in_table:
                    out.write('</table>\n')
                    in_table = False
            else:
                if in_table:
                    out.write('</table>\n')
                    in_table = False
                if line.strip():
                    out.write(f'<pre>{html.escape(line)}</pre>\n')
        
        if in_table:
            out.write('</table>\n')
        out.write('</body></html>\n')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: convert_tbl_to_html.py <input.tbl> <output.html>")
        sys.exit(1)
    convert_tbl_to_html(sys.argv[1], sys.argv[2])
