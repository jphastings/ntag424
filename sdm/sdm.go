package sdm

import (
	"bytes"
	"errors"
	"text/template"
	"text/template/parse"
)

var (
	ErrUnsupportedTemplateString = errors.New("unsupported template string")
	ErrDuplicateSubstitution     = errors.New("variable substituted more than once")
)

type MirrorString struct {
	string
	Positions map[string]int
}

// Provide a string with
func ParseMirrorString(str string) (*MirrorString, error) {
	tmpl, err := template.New("mirror").Parse(str)
	if err != nil {
		return nil, err
	}

	// All values must be strings
	vars := map[string]interface{}{
		"UID":     "[ uid ]",
		"Counter": "[c]",
		"PICC":    "0[ uid ][c]",
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, vars); err != nil {
		return nil, err
	}

	ms := &MirrorString{
		string:    out.String(),
		Positions: make(map[string]int),
	}

	lengthDelta := 0
	stringLen := 0
	for _, node := range tmpl.Tree.Root.Nodes {
		switch node.Type() {
		case parse.NodeText:
			stringLen += len(node.String())

		case parse.NodeAction:
			i, err := actionNodeToIdent(node)
			if err != nil {
				return nil, err
			}

			val, ok := vars[i]
			if !ok {
				return nil, ErrUnsupportedTemplateString
			}
			ms.Positions[i] = stringLen + lengthDelta

			nodeLen := len(node.String())
			lengthDelta += len(val.(string)) - nodeLen
			stringLen += nodeLen

		default:
			return nil, ErrUnsupportedTemplateString
		}
	}

	return ms, nil
}

func (ms *MirrorString) String() string {
	return ms.string
}

func actionNodeToIdent(node parse.Node) (string, error) {
	a := node.(*parse.ActionNode)
	if len(a.Pipe.Cmds) != 1 {
		return "", ErrUnsupportedTemplateString
	}

	cmd := a.Pipe.Cmds[0]
	if len(cmd.Args) != 1 {
		return "", ErrUnsupportedTemplateString
	}

	field := cmd.Args[0].(*parse.FieldNode)
	if len(field.Ident) != 1 {
		return "", ErrUnsupportedTemplateString
	}

	return field.Ident[0], nil
}
