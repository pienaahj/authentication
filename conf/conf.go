package conf

import "html/template"

// TPL pointer to templates
var TPL *template.Template

func init() {
	TPL = template.Must(template.ParseGlob("templates/*.gohtml"))
}
