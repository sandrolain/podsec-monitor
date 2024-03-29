package mail

import (
	"fmt"
	"html"
	"strings"

	"github.com/sandrolain/podsec-monitor/src/internal/grype"
	"github.com/sandrolain/podsec-monitor/src/internal/severity"
	"github.com/sandrolain/podsec-monitor/src/models"
	"github.com/vanng822/go-premailer/premailer"
	"github.com/wneessen/go-mail"
)

type MailResult struct {
	Rest   int
	Result grype.Result
}

func GenerateMail(cfg models.Config, results []MailResult, processedImages map[string]string) (res string, err error) {
	tables := make([]string, len(results))

	for i, item := range results {
		result := item.Result
		matches := result.Matches

		imageWithTag, ok := processedImages[result.Target.UserInput]
		if !ok {
			imageWithTag = result.Target.UserInput
		}

		table := fmt.Sprintf(`
			<h3>%s<br>%s<br>%s</h3>
			<table class="data-table"><thead>
				<tr><th>Severity</th><th>Vul ID</th><th>Package</th><th>Version</th><th>Type</th></tr>
			</thead><tbody>`, imageWithTag, result.Target.UserInput, result.Target.ImageID)

		for _, res := range matches {
			sev := res.Vulnerability.Severity
			table += fmt.Sprintf("<tr><td>%s %s</td>", severity.GetSeverityEmoji(sev), html.EscapeString(sev))
			table += fmt.Sprintf("<td><a href=\"%s\">%s</a></td>", html.EscapeString(res.Vulnerability.DataSource), html.EscapeString(res.Vulnerability.Id))
			table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Name))
			table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Version))
			table += fmt.Sprintf("<td>%s</td></tr>", html.EscapeString(res.Artifact.Type))
		}

		if item.Rest > 0 {
			table += fmt.Sprintf("<tr><td colspan=\"5\">%d more vulnerabilities</td></tr>", item.Rest)
		}

		table += "</tbody></table>"

		tables[i] = table
	}

	html := mailHtml(strings.Join(tables, ""))

	prem, err := premailer.NewPremailerFromString(html, premailer.NewOptions())
	if err != nil {
		return
	}

	res, err = prem.Transform()
	return
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

type SendMailArgs struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	Subject  string
	Body     string
	Files    []string
}

func SendEmail(args SendMailArgs) (err error) {
	m := mail.NewMsg()
	if err = m.From(args.From); err != nil {
		return
	}
	if err = m.To(args.To...); err != nil {
		return
	}
	m.Subject(args.Subject)
	m.SetBodyString(mail.TypeTextHTML, args.Body)

	for _, file := range args.Files {
		m.AttachFile(file)
	}

	opts := []mail.Option{}

	//opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain))
	opts = append(opts, mail.WithTLSPortPolicy(mail.NoTLS))
	opts = append(opts, mail.WithPort(args.Port))

	if args.Username != "" {
		opts = append(opts, mail.WithUsername(args.Username))
	}
	if args.Password != "" {
		opts = append(opts, mail.WithPassword(args.Password))
	}

	c, err := mail.NewClient(args.Host, opts...)
	if err != nil {
		return
	}

	err = c.DialAndSend(m)

	return
}
