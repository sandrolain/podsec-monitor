package mail

import (
	"fmt"
	"html"
	"slices"
	"sort"
	"strings"

	"github.com/sandrolain/podsec-monitor/src/internal/grype"
	"github.com/sandrolain/podsec-monitor/src/internal/severity"
)

func GenerateMail(results []grype.Result, processedImages map[string]string, minSeverity int) string {
	tables := make([]string, len(results))

	for i, result := range results {
		matches := result.Matches

		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Vulnerability.Severity == matches[j].Vulnerability.Severity {
				return matches[i].Vulnerability.Id < matches[j].Vulnerability.Id
			}
			return severity.GetSeverityIndex(matches[i].Vulnerability.Severity) > severity.GetSeverityIndex(matches[j].Vulnerability.Severity)
		})

		matches = slices.DeleteFunc(matches, func(match grype.Match) bool {
			return severity.GetSeverityIndex(match.Vulnerability.Severity) < minSeverity
		})

		imageWithTag, ok := processedImages[result.Source.Target.UserInput]
		if !ok {
			imageWithTag = result.Source.Target.UserInput
		}

		table := fmt.Sprintf(`
			<h3>%s<br>%s<br>%s</h3>
			<table class="data-table"><thead>
				<tr><th>Severity</th><th>Vul ID</th><th>Package</th><th>Version</th><th>Type</th></tr>
			</thead><tbody>`, imageWithTag, result.Source.Target.UserInput, result.Source.Target.ImageID)

		for _, res := range matches {
			sev := res.Vulnerability.Severity
			table += fmt.Sprintf("<tr><td>%s %s</td>", severity.GetSeverityEmoji(sev), html.EscapeString(sev))
			table += fmt.Sprintf("<td><a href=\"%s\">%s</a></td>", html.EscapeString(res.Vulnerability.DataSource), html.EscapeString(res.Vulnerability.Id))
			table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Name))
			table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Version))
			table += fmt.Sprintf("<td>%s</td></tr>", html.EscapeString(res.Artifact.Type))
		}

		table += "</tbody></table>"

		tables[i] = table
	}

	return mailHtml(strings.Join(tables, ""))
}

func mailHtml(body string) string {
	return `
	<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
	<html xmlns="http://www.w3.org/1999/xhtml">
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<style type="text/css" rel="stylesheet" media="all">
		*:not(br):not(tr):not(html) {
			font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif;
			-webkit-box-sizing: border-box;
			box-sizing: border-box;
		}
		body {
			width: 100% !important;
			height: 100%;
			margin: 0;
			line-height: 1.4;
			background-color: #FFFFFF;
			-webkit-text-size-adjust: none;
			font-size: 12px;
		}
		a {
			color: #3869D4;
		}
		h3 {
			font-size: 14px
		}
		.data-table {
			font-size: 12px;
      width: 100%;
      margin: 0;
      border-spacing: 0;
      border-collapse: collapse;
			background-color: #FFFFFF;
    }
    .data-table th {
      text-align: left;
      padding: 0px 5px;
      padding-bottom: 8px;
      border-bottom: 1px solid #EDEFF2;
    }
    .data-table td {
      padding: 10px 5px;
      font-size: 12px;
      line-height: 12px;
      border: 1px solid #EDEFF2;
      white-space: nowrap;
    }
    .data-table tr:nth-child(odd) td {
      background-color: #F4F4F7;
    }
		</style>
		<table class="email-body_inner" align="center" width="570" cellpadding="0" cellspacing="0">
    <tr><td>` + body + `</td></tr></table>
		</body>
		</html>
		`

}
