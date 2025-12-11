<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container License Report</title>
    <style>
        body { font-family: Arial, Helvetica, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .blocking { background-color: #ffcccc; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Container License Compliance Report</h1>
    <p><strong>Image:</strong> {{ .ArtifactName }}</p>
    <p><strong>Scan Date:</strong> {{ .CreatedAt }}</p>
    <p>This report lists all detected licenses in the container image. Licenses marked as blocking (AGPL, SSPL, Proprietary, Commercial, Elastic) are highlighted in red and may require further evaluation for compliance and risk assessment.</p>
    
    <table>
        <thead>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>License</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {{ range .Results }}
                {{ range .Licenses }}
                <tr {{ if or (eq .License "AGPL") (eq .License "SSPL") (eq .License "Proprietary") (eq .License "Commercial") (eq .License "Elastic") }}class="blocking"{{ end }}>
                    <td>{{ .PkgName }}</td>
                    <td>{{ .PkgVersion }}</td>
                    <td>{{ .License }}</td>
                    <td>
                        {{ if or (eq .License "AGPL") (eq .License "SSPL") (eq .License "Proprietary") (eq .License "Commercial") (eq .License "Elastic") }}
                        <span class="warning">BLOCKING - Requires Review</span>
                        {{ else }}
                        Compliant
                        {{ end }}
                    </td>
                </tr>
                {{ end }}
            {{ end }}
        </tbody>
    </table>
    
    <h2>Risk Evaluation Notes</h2>
    <ul>
        <li><strong>Blocking Licenses:</strong> AGPL, SSPL, Proprietary, Commercial, Elastic - These may impose restrictions on usage, distribution, or require source code disclosure. Evaluate impact on your organization's policies.</li>
        <li><strong>Permissive Licenses:</strong> MIT, BSD, Apache - Generally low risk, but verify compatibility with your software stack.</li>
        <li><strong>Copyleft Licenses:</strong> GPL variants - May require derivative works to be open-source.</li>
        <li><strong>Recommendations:</strong> Consult legal counsel for licenses flagged as blocking. Consider using alternative images or negotiating with vendors if necessary.</li>
    </ul>
</body>
</html>
