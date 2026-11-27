// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rungvx

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"net/url"
	"reflect"
	"slices"
	"strings"
	tmplparse "text/template/parse"
	"time"
	"unicode/utf8"
)

const maxTemplateDepth = 1000

// formatTemplate evaluates parsed Go template syntax without importing
// text/template or calling reflect Method/MethodByName, keeping cmd/link
// dead-method elimination active across the binary.
type formatTemplate struct {
	tree  *tmplparse.Tree
	trees map[string]*tmplparse.Tree
}

var (
	errRangeBreak    = errors.New("break")
	errRangeContinue = errors.New("continue")
	errorType        = reflect.TypeFor[error]()
	fmtStringerType  = reflect.TypeFor[fmt.Stringer]()
)

var formatBuiltinPlaceholders = map[string]any{
	"json":     struct{}{},
	"lower":    struct{}{},
	"upper":    struct{}{},
	"join":     struct{}{},
	"split":    struct{}{},
	"truncate": struct{}{},
	"and":      struct{}{},
	"or":       struct{}{},
	"not":      struct{}{},
	"len":      struct{}{},
	"index":    struct{}{},
	"slice":    struct{}{},
	"eq":       struct{}{},
	"ne":       struct{}{},
	"lt":       struct{}{},
	"le":       struct{}{},
	"gt":       struct{}{},
	"ge":       struct{}{},
	"print":    struct{}{},
	"printf":   struct{}{},
	"println":  struct{}{},
	"html":     struct{}{},
	"js":       struct{}{},
	"urlquery": struct{}{},
}

func parseFormatTemplate(spec string) (*formatTemplate, error) {
	trees, err := tmplparse.Parse("format", spec, "{{", "}}", formatBuiltinPlaceholders)
	if err != nil {
		return nil, err
	}
	tree := trees["format"]
	if tree == nil || tree.Root == nil {
		return nil, errors.New("empty template")
	}
	return &formatTemplate{tree: tree, trees: trees}, nil
}

func (t *formatTemplate) Execute(w io.Writer, data any) error {
	root := reflect.ValueOf(data)
	st := &templateEvalState{
		tmpl: t,
		wr:   w,
		vars: []templateVar{{name: "$", value: root}},
	}
	err := st.walk(root, t.tree.Root)
	if errors.Is(err, errRangeBreak) || errors.Is(err, errRangeContinue) {
		return errors.New("break or continue outside range")
	}
	return err
}

type templateVar struct {
	name  string
	value reflect.Value
}

type templateEvalState struct {
	tmpl  *formatTemplate
	wr    io.Writer
	vars  []templateVar
	depth int
}

func (s *templateEvalState) mark() int {
	return len(s.vars)
}

func (s *templateEvalState) pop(mark int) {
	s.vars = s.vars[:mark]
}

func (s *templateEvalState) push(name string, value reflect.Value) {
	s.vars = append(s.vars, templateVar{name: name, value: value})
}

func (s *templateEvalState) setVar(name string, value reflect.Value) {
	for i := len(s.vars) - 1; i >= 0; i-- {
		if s.vars[i].name == name {
			s.vars[i].value = value
			return
		}
	}
	s.push(name, value)
}

func (s *templateEvalState) setTopVar(n int, value reflect.Value) {
	s.vars[len(s.vars)-n].value = value
}

func (s *templateEvalState) varValue(name string) (reflect.Value, error) {
	for i := len(s.vars) - 1; i >= 0; i-- {
		if s.vars[i].name == name {
			return s.vars[i].value, nil
		}
	}
	return reflect.Value{}, fmt.Errorf("undefined variable: %s", name)
}

func (s *templateEvalState) walk(dot reflect.Value, node tmplparse.Node) error {
	switch n := node.(type) {
	case *tmplparse.ListNode:
		if n == nil {
			return nil
		}
		for _, child := range n.Nodes {
			if err := s.walk(dot, child); err != nil {
				return err
			}
		}
		return nil
	case *tmplparse.TextNode:
		_, err := s.wr.Write(n.Text)
		return err
	case *tmplparse.CommentNode:
		return nil
	case *tmplparse.ActionNode:
		val, err := s.evalPipeline(dot, n.Pipe)
		if err != nil {
			return err
		}
		if len(n.Pipe.Decl) == 0 {
			return s.printValue(val)
		}
		return nil
	case *tmplparse.IfNode:
		return s.walkIfOrWith(tmplparse.NodeIf, dot, n.Pipe, n.List, n.ElseList)
	case *tmplparse.WithNode:
		return s.walkIfOrWith(tmplparse.NodeWith, dot, n.Pipe, n.List, n.ElseList)
	case *tmplparse.RangeNode:
		return s.walkRange(dot, n)
	case *tmplparse.TemplateNode:
		return s.walkTemplate(dot, n)
	case *tmplparse.BreakNode:
		return errRangeBreak
	case *tmplparse.ContinueNode:
		return errRangeContinue
	default:
		return fmt.Errorf("unsupported template node %T", node)
	}
}

func (s *templateEvalState) walkTemplate(dot reflect.Value, t *tmplparse.TemplateNode) error {
	sub := s.tmpl.trees[t.Name]
	if sub == nil || sub.Root == nil {
		return fmt.Errorf("template %q not defined", t.Name)
	}
	if s.depth >= maxTemplateDepth {
		return fmt.Errorf("exceeded maximum template depth (%d)", maxTemplateDepth)
	}
	dotVal, err := s.evalPipeline(dot, t.Pipe)
	if err != nil {
		return err
	}
	child := &templateEvalState{
		tmpl:  s.tmpl,
		wr:    s.wr,
		vars:  []templateVar{{name: "$", value: dotVal}},
		depth: s.depth + 1,
	}
	return child.walk(dotVal, sub.Root)
}

func (s *templateEvalState) walkIfOrWith(typ tmplparse.NodeType, dot reflect.Value, pipe *tmplparse.PipeNode, list, elseList *tmplparse.ListNode) error {
	mark := s.mark()
	defer s.pop(mark)
	val, err := s.evalPipeline(dot, pipe)
	if err != nil {
		return err
	}
	if isTemplateTruthy(val) {
		if typ == tmplparse.NodeWith {
			return s.walk(val, list)
		}
		return s.walk(dot, list)
	}
	if elseList != nil {
		return s.walk(dot, elseList)
	}
	return nil
}

func (s *templateEvalState) walkRange(dot reflect.Value, r *tmplparse.RangeNode) error {
	mark := s.mark()
	defer s.pop(mark)
	val, err := s.evalPipeline(dot, r.Pipe)
	if err != nil {
		return err
	}
	val, isNil := indirectValue(val)
	if isNil || !val.IsValid() {
		if r.ElseList != nil {
			return s.walk(dot, r.ElseList)
		}
		return nil
	}

	oneIteration := func(index, elem reflect.Value) (bool, error) {
		if len(r.Pipe.Decl) > 0 {
			if r.Pipe.IsAssign {
				if len(r.Pipe.Decl) > 1 {
					s.setVar(r.Pipe.Decl[0].Ident[0], index)
				}
				s.setVar(r.Pipe.Decl[len(r.Pipe.Decl)-1].Ident[0], elem)
			} else {
				if len(r.Pipe.Decl) > 1 {
					s.setTopVar(2, index)
				}
				s.setTopVar(1, elem)
			}
		}
		iterMark := s.mark()
		err := s.walk(elem, r.List)
		s.pop(iterMark)
		if errors.Is(err, errRangeBreak) {
			return true, nil
		}
		if errors.Is(err, errRangeContinue) {
			return false, nil
		}
		return false, err
	}

	switch val.Kind() {
	case reflect.Array, reflect.Slice:
		if val.Len() == 0 {
			break
		}
		for i := range val.Len() {
			stop, err := oneIteration(reflect.ValueOf(i), val.Index(i))
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		return nil
	case reflect.Map:
		if val.Len() == 0 {
			break
		}
		keys := val.MapKeys()
		slices.SortFunc(keys, compareMapKeys)
		for _, k := range keys {
			stop, err := oneIteration(k, val.MapIndex(k))
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if len(r.Pipe.Decl) > 1 {
			return fmt.Errorf("can't use two variables to range over %v", val.Type())
		}
		n := val.Int()
		if n <= 0 {
			break
		}
		for i := range n {
			v := reflect.ValueOf(i).Convert(val.Type())
			stop, err := oneIteration(v, v)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if len(r.Pipe.Decl) > 1 {
			return fmt.Errorf("can't use two variables to range over %v", val.Type())
		}
		n := val.Uint()
		if n == 0 {
			break
		}
		for i := range n {
			v := reflect.ValueOf(i).Convert(val.Type())
			stop, err := oneIteration(v, v)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		return nil
	case reflect.Chan:
		if val.IsNil() {
			break
		}
		if val.Type().ChanDir() == reflect.SendDir {
			return fmt.Errorf("range over send-only channel %v", val.Type())
		}
		i := 0
		for ; ; i++ {
			elem, ok := val.Recv()
			if !ok {
				break
			}
			stop, err := oneIteration(reflect.ValueOf(i), elem)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		if i > 0 {
			return nil
		}
	default:
		return fmt.Errorf("range can't iterate over %v", val.Type())
	}

	if r.ElseList != nil {
		return s.walk(dot, r.ElseList)
	}
	return nil
}

func (s *templateEvalState) evalPipeline(dot reflect.Value, pipe *tmplparse.PipeNode) (reflect.Value, error) {
	if pipe == nil {
		return reflect.Value{}, nil
	}
	var val reflect.Value
	for i, cmd := range pipe.Cmds {
		var err error
		val, err = s.evalCommand(dot, cmd, i > 0, val)
		if err != nil {
			return reflect.Value{}, err
		}
		if val.IsValid() && val.Kind() == reflect.Interface && val.NumMethod() == 0 {
			val = val.Elem()
		}
	}
	for _, variable := range pipe.Decl {
		if pipe.IsAssign {
			s.setVar(variable.Ident[0], val)
		} else {
			s.push(variable.Ident[0], val)
		}
	}
	return val, nil
}

func (s *templateEvalState) evalCommand(dot reflect.Value, cmd *tmplparse.CommandNode, hasFinal bool, final reflect.Value) (reflect.Value, error) {
	if len(cmd.Args) == 0 {
		return reflect.Value{}, errors.New("empty command")
	}
	first := cmd.Args[0]
	switch n := first.(type) {
	case *tmplparse.IdentifierNode:
		return s.evalBuiltin(dot, n.Ident, cmd.Args[1:], hasFinal, final)
	case *tmplparse.FieldNode:
		return s.evalFieldChainWithArgs(dot, n.Ident, cmd.Args[1:], hasFinal, final)
	case *tmplparse.ChainNode:
		base, err := s.evalArg(dot, n.Node)
		if err != nil {
			return reflect.Value{}, err
		}
		return s.evalFieldChainWithArgs(dot, n.Field, cmd.Args[1:], hasFinal, final, base)
	case *tmplparse.VariableNode:
		return s.evalVariableNodeWithArgs(dot, n, cmd.Args[1:], hasFinal, final)
	case *tmplparse.PipeNode:
		if len(cmd.Args) > 1 || hasFinal {
			return reflect.Value{}, errors.New("parenthesized pipeline cannot take arguments")
		}
		return s.evalPipeline(dot, n)
	case *tmplparse.NilNode:
		return reflect.Value{}, errors.New("nil is not a command")
	default:
		if len(cmd.Args) > 1 || hasFinal {
			return reflect.Value{}, fmt.Errorf("cannot give argument to non-function %s", first)
		}
		return s.evalArg(dot, first)
	}
}

func (s *templateEvalState) evalArg(dot reflect.Value, arg tmplparse.Node) (reflect.Value, error) {
	switch n := arg.(type) {
	case *tmplparse.DotNode:
		return dot, nil
	case *tmplparse.NilNode:
		return reflect.Value{}, nil
	case *tmplparse.BoolNode:
		return reflect.ValueOf(n.True), nil
	case *tmplparse.StringNode:
		return reflect.ValueOf(n.Text), nil
	case *tmplparse.NumberNode:
		return evalNumberNode(n)
	case *tmplparse.FieldNode:
		return s.evalFieldChainWithArgs(dot, n.Ident, nil, false, reflect.Value{})
	case *tmplparse.ChainNode:
		base, err := s.evalArg(dot, n.Node)
		if err != nil {
			return reflect.Value{}, err
		}
		return s.evalFieldChainWithArgs(dot, n.Field, nil, false, reflect.Value{}, base)
	case *tmplparse.VariableNode:
		return s.evalVariableNodeWithArgs(dot, n, nil, false, reflect.Value{})
	case *tmplparse.PipeNode:
		return s.evalPipeline(dot, n)
	case *tmplparse.IdentifierNode:
		return s.evalBuiltin(dot, n.Ident, nil, false, reflect.Value{})
	default:
		return reflect.Value{}, fmt.Errorf("unsupported argument %T", arg)
	}
}

func isHexInt(s string) bool {
	return len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && !strings.ContainsAny(s, "pP")
}

func isRuneInt(s string) bool {
	return len(s) > 0 && s[0] == '\''
}

func evalNumberNode(n *tmplparse.NumberNode) (reflect.Value, error) {
	switch {
	case n.IsComplex:
		return reflect.ValueOf(n.Complex128), nil
	case n.IsFloat && !isHexInt(n.Text) && !isRuneInt(n.Text) && strings.ContainsAny(n.Text, ".eEpP"):
		return reflect.ValueOf(n.Float64), nil
	case n.IsInt:
		v := int(n.Int64)
		if int64(v) != n.Int64 {
			return reflect.Value{}, fmt.Errorf("%s overflows int", n.Text)
		}
		return reflect.ValueOf(v), nil
	case n.IsUint:
		return reflect.ValueOf(n.Uint64), nil
	default:
		return reflect.Value{}, fmt.Errorf("invalid number %q", n.Text)
	}
}

func (s *templateEvalState) evalVariableNodeWithArgs(dot reflect.Value, n *tmplparse.VariableNode, argNodes []tmplparse.Node, hasFinal bool, final reflect.Value) (reflect.Value, error) {
	val, err := s.varValue(n.Ident[0])
	if err != nil {
		return reflect.Value{}, err
	}
	if len(n.Ident) == 1 {
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, fmt.Errorf("variable %s cannot take arguments", n)
		}
		return val, nil
	}
	return s.evalFieldChainWithArgs(dot, n.Ident[1:], argNodes, hasFinal, final, val)
}

func (s *templateEvalState) evalFieldChainWithArgs(dot reflect.Value, ident []string, argNodes []tmplparse.Node, hasFinal bool, final reflect.Value, explicitBase ...reflect.Value) (reflect.Value, error) {
	cur := dot
	if len(explicitBase) > 0 {
		cur = explicitBase[0]
	}
	for i, name := range ident {
		isLast := i == len(ident)-1
		var stepArgs []tmplparse.Node
		stepHasFinal := false
		if isLast {
			stepArgs = argNodes
			stepHasFinal = hasFinal
		}
		var err error
		cur, err = s.evalField(dot, cur, name, stepArgs, stepHasFinal, final)
		if err != nil {
			return reflect.Value{}, err
		}
	}
	return cur, nil
}

func (s *templateEvalState) evalField(dot, receiver reflect.Value, fieldName string, argNodes []tmplparse.Node, hasFinal bool, final reflect.Value) (reflect.Value, error) {
	if !receiver.IsValid() {
		return reflect.Value{}, fmt.Errorf("nil data; no entry for key %q", fieldName)
	}
	val, isNil := indirectValue(receiver)
	if isNil {
		return reflect.Value{}, fmt.Errorf("nil pointer evaluating %s.%s", receiver.Type(), fieldName)
	}

	// Support common read-only time.Time methods explicitly without reflect.MethodByName.
	if val.CanInterface() {
		if ts, ok := val.Interface().(time.Time); ok {
			if res, handled, err := s.evalTimeMethod(dot, ts, fieldName, argNodes, hasFinal, final); handled {
				return res, err
			}
		}
	}

	if len(argNodes) > 0 || hasFinal {
		return reflect.Value{}, fmt.Errorf("%s is not a method but has arguments", fieldName)
	}

	switch val.Kind() {
	case reflect.Struct:
		sf, ok := val.Type().FieldByName(fieldName)
		if !ok {
			return reflect.Value{}, fmt.Errorf("can't evaluate field %s in type %s", fieldName, val.Type())
		}
		if !sf.IsExported() {
			return reflect.Value{}, fmt.Errorf("%s is an unexported field of struct type %s", fieldName, val.Type())
		}
		return fieldByIndexSafe(val, sf.Index)
	case reflect.Map:
		keyType := val.Type().Key()
		nameVal := reflect.ValueOf(fieldName)
		if !nameVal.Type().AssignableTo(keyType) {
			if nameVal.Type().ConvertibleTo(keyType) && keyType.Kind() == reflect.String {
				nameVal = nameVal.Convert(keyType)
			} else {
				return reflect.Value{}, fmt.Errorf("can't evaluate field %s in map with key type %s", fieldName, keyType)
			}
		}
		res := val.MapIndex(nameVal)
		if !res.IsValid() {
			return reflect.Value{}, fmt.Errorf("map has no entry for key %q", fieldName)
		}
		return res, nil
	default:
		return reflect.Value{}, fmt.Errorf("can't evaluate field %s in type %s", fieldName, val.Type())
	}
}

func (s *templateEvalState) evalTimeMethod(dot reflect.Value, ts time.Time, method string, argNodes []tmplparse.Node, hasFinal bool, final reflect.Value) (reflect.Value, bool, error) {
	collectArgs := func() ([]reflect.Value, error) {
		args := make([]reflect.Value, 0, len(argNodes)+1)
		for _, an := range argNodes {
			v, err := s.evalArg(dot, an)
			if err != nil {
				return nil, err
			}
			args = append(args, v)
		}
		if hasFinal {
			args = append(args, final)
		}
		return args, nil
	}

	switch method {
	case "Format":
		args, err := collectArgs()
		if err != nil {
			return reflect.Value{}, true, err
		}
		layout, err := requireOneString("Format", args)
		if err != nil {
			return reflect.Value{}, true, err
		}
		return reflect.ValueOf(ts.Format(layout)), true, nil
	case "UTC":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for UTC: want 0")
		}
		return reflect.ValueOf(ts.UTC()), true, nil
	case "Local":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for Local: want 0")
		}
		return reflect.ValueOf(ts.Local()), true, nil
	case "Unix":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for Unix: want 0")
		}
		return reflect.ValueOf(ts.Unix()), true, nil
	case "UnixMilli":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for UnixMilli: want 0")
		}
		return reflect.ValueOf(ts.UnixMilli()), true, nil
	case "UnixNano":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for UnixNano: want 0")
		}
		return reflect.ValueOf(ts.UnixNano()), true, nil
	case "IsZero":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for IsZero: want 0")
		}
		return reflect.ValueOf(ts.IsZero()), true, nil
	case "String":
		if len(argNodes) > 0 || hasFinal {
			return reflect.Value{}, true, errors.New("wrong number of args for String: want 0")
		}
		return reflect.ValueOf(ts.String()), true, nil
	default:
		return reflect.Value{}, false, nil
	}
}

func fieldByIndexSafe(v reflect.Value, index []int) (reflect.Value, error) {
	cur := v
	for _, i := range index {
		if cur.Kind() == reflect.Pointer {
			if cur.IsNil() {
				return reflect.Value{}, fmt.Errorf("nil pointer evaluating embedded field in type %s", v.Type())
			}
			cur = cur.Elem()
		}
		cur = cur.Field(i)
	}
	return cur, nil
}

func indirectValue(v reflect.Value) (reflect.Value, bool) {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return v, true
		}
		v = v.Elem()
	}
	return v, !v.IsValid()
}

func indirectInterface(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	if v.Kind() == reflect.Interface {
		return v.Elem()
	}
	return v
}

func printableValue(v reflect.Value) (any, bool) {
	if !v.IsValid() {
		return nil, true
	}
	if v.Kind() == reflect.Pointer {
		v, _ = indirectForPrint(v)
	}
	if !v.IsValid() {
		return nil, true
	}
	if !v.Type().Implements(errorType) && !v.Type().Implements(fmtStringerType) {
		if v.CanAddr() && (reflect.PointerTo(v.Type()).Implements(errorType) || reflect.PointerTo(v.Type()).Implements(fmtStringerType)) {
			v = v.Addr()
		} else {
			switch v.Kind() {
			case reflect.Chan, reflect.Func:
				return nil, false
			}
		}
	}
	return v.Interface(), true
}

func indirectForPrint(v reflect.Value) (reflect.Value, bool) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return v, true
		}
		if v.Type().NumMethod() > 0 && v.CanInterface() {
			if _, ok := v.Interface().(error); ok {
				return v, false
			}
			if _, ok := v.Interface().(fmt.Stringer); ok {
				return v, false
			}
		}
		v = v.Elem()
	}
	return v, false
}

func (s *templateEvalState) printValue(v reflect.Value) error {
	if !v.IsValid() {
		_, err := io.WriteString(s.wr, "<no value>")
		return err
	}
	iface, ok := printableValue(v)
	if !ok {
		return fmt.Errorf("can't print value of type %s", v.Type())
	}
	if iface == nil {
		_, err := io.WriteString(s.wr, "<no value>")
		return err
	}
	_, err := fmt.Fprint(s.wr, iface)
	return err
}

func (s *templateEvalState) evalBuiltin(dot reflect.Value, name string, argNodes []tmplparse.Node, hasFinal bool, final reflect.Value) (reflect.Value, error) {
	// Evaluate short-circuiting boolean operators lazily to match Go text/template.
	if name == "and" || name == "or" {
		total := len(argNodes)
		if hasFinal {
			total++
		}
		if total == 0 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for %s: want at least 1 got 0", name)
		}
		var last reflect.Value
		for i := range total {
			var cur reflect.Value
			if i < len(argNodes) {
				var err error
				cur, err = s.evalArg(dot, argNodes[i])
				if err != nil {
					return reflect.Value{}, err
				}
			} else {
				cur = final
			}
			last = cur
			truth := isTemplateTruthy(cur)
			if name == "and" && !truth {
				return cur, nil
			}
			if name == "or" && truth {
				return cur, nil
			}
		}
		return last, nil
	}

	args := make([]reflect.Value, 0, len(argNodes)+1)
	for _, an := range argNodes {
		v, err := s.evalArg(dot, an)
		if err != nil {
			return reflect.Value{}, err
		}
		args = append(args, v)
	}
	if hasFinal {
		args = append(args, final)
	}

	switch name {
	case "json":
		if len(args) != 1 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for json: want 1 got %d", len(args))
		}
		var raw any
		if args[0].IsValid() {
			raw = args[0].Interface()
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(raw); err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(strings.TrimSuffix(buf.String(), "\n")), nil
	case "lower":
		str, err := requireOneString("lower", args)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(strings.ToLower(str)), nil
	case "upper":
		str, err := requireOneString("upper", args)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(strings.ToUpper(str)), nil
	case "join":
		if len(args) != 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for join: want 2 got %d", len(args))
		}
		elems, err := requireStringSlice("join", args[0])
		if err != nil {
			return reflect.Value{}, err
		}
		sep, err := requireString("join", args[1])
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(strings.Join(elems, sep)), nil
	case "split":
		if len(args) != 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for split: want 2 got %d", len(args))
		}
		str, err := requireString("split", args[0])
		if err != nil {
			return reflect.Value{}, err
		}
		sep, err := requireString("split", args[1])
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(strings.Split(str, sep)), nil
	case "truncate":
		if len(args) != 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for truncate: want 2 got %d", len(args))
		}
		str, err := requireString("truncate", args[0])
		if err != nil {
			return reflect.Value{}, err
		}
		maxLen, err := requireInt("truncate", args[1])
		if err != nil {
			return reflect.Value{}, err
		}
		if maxLen <= 0 {
			return reflect.ValueOf(""), nil
		}
		runes := []rune(str)
		if len(runes) <= maxLen {
			return reflect.ValueOf(str), nil
		}
		return reflect.ValueOf(string(runes[:maxLen])), nil
	case "not":
		if len(args) != 1 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for not: want 1 got %d", len(args))
		}
		return reflect.ValueOf(!isTemplateTruthy(args[0])), nil
	case "len":
		if len(args) != 1 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for len: want 1 got %d", len(args))
		}
		return evalLen(args[0])
	case "index":
		if len(args) < 1 {
			return reflect.Value{}, errors.New("wrong number of args for index: want at least 1 got 0")
		}
		return evalIndex(args[0], args[1:])
	case "slice":
		if len(args) < 1 || len(args) > 4 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for slice: got %d", len(args))
		}
		return evalSlice(args[0], args[1:])
	case "eq":
		if len(args) < 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for eq: want at least 2 got %d", len(args))
		}
		for _, rhs := range args[1:] {
			ok, err := valuesEqual(args[0], rhs)
			if err != nil {
				return reflect.Value{}, err
			}
			if ok {
				return reflect.ValueOf(true), nil
			}
		}
		return reflect.ValueOf(false), nil
	case "ne":
		if len(args) != 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for ne: want 2 got %d", len(args))
		}
		ok, err := valuesEqual(args[0], args[1])
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(!ok), nil
	case "lt", "le", "gt", "ge":
		if len(args) != 2 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for %s: want 2 got %d", name, len(args))
		}
		ok, err := evalOrderedComparison(name, args[0], args[1])
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(ok), nil
	case "print":
		return reflect.ValueOf(fmt.Sprint(rawArgs(args)...)), nil
	case "println":
		return reflect.ValueOf(fmt.Sprintln(rawArgs(args)...)), nil
	case "printf":
		if len(args) < 1 {
			return reflect.Value{}, errors.New("wrong number of args for printf: want at least 1 got 0")
		}
		formatStr, err := requireString("printf", args[0])
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(fmt.Sprintf(formatStr, rawArgs(args[1:])...)), nil
	case "html":
		vals, err := printableArgs(args)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(html.EscapeString(evalEscaperInput(vals))), nil
	case "js":
		vals, err := printableArgs(args)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(jsEscapeString(evalEscaperInput(vals))), nil
	case "urlquery":
		vals, err := printableArgs(args)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(url.QueryEscape(evalEscaperInput(vals))), nil
	default:
		return reflect.Value{}, fmt.Errorf("function %q not defined", name)
	}
}

func rawArgs(vals []reflect.Value) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		if v.IsValid() {
			out[i] = v.Interface()
		}
	}
	return out
}

func printableArgs(vals []reflect.Value) ([]any, error) {
	out := make([]any, len(vals))
	for i, v := range vals {
		if !v.IsValid() {
			continue
		}
		iface, ok := printableValue(v)
		if !ok {
			return nil, fmt.Errorf("can't print value of type %s", v.Type())
		}
		out[i] = iface
	}
	return out, nil
}

func evalEscaperInput(args []any) string {
	if len(args) == 1 {
		if s, ok := args[0].(string); ok {
			return s
		}
	}
	return fmt.Sprint(args...)
}

func jsEscapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	const hexDigits = "0123456789ABCDEF"
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[s[i]>>4])
			b.WriteByte(hexDigits[s[i]&0x0f])
			i++
			continue
		}
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '<':
			b.WriteString(`\u003C`)
		case '>':
			b.WriteString(`\u003E`)
		case '&':
			b.WriteString(`\u0026`)
		case '=':
			b.WriteString(`\u003D`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteString(s[i : i+size])
			}
		}
		i += size
	}
	return b.String()
}

func requireOneString(fn string, args []reflect.Value) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("wrong number of args for %s: want 1 got %d", fn, len(args))
	}
	return requireString(fn, args[0])
}

func requireString(fn string, v reflect.Value) (string, error) {
	v, isNil := indirectValue(v)
	if isNil || v.Kind() != reflect.String {
		return "", fmt.Errorf("%s expects a string argument", fn)
	}
	return v.String(), nil
}

func requireStringSlice(fn string, v reflect.Value) ([]string, error) {
	v, isNil := indirectValue(v)
	if isNil {
		return nil, nil
	}
	if v.Kind() != reflect.Slice || v.Type().Elem().Kind() != reflect.String {
		return nil, fmt.Errorf("%s expects a []string argument", fn)
	}
	if s, ok := v.Interface().([]string); ok {
		return s, nil
	}
	out := make([]string, v.Len())
	for i := range v.Len() {
		out[i] = v.Index(i).String()
	}
	return out, nil
}

func requireInt(fn string, v reflect.Value) (int, error) {
	v = indirectInterface(v)
	if !v.IsValid() {
		return 0, fmt.Errorf("%s expects an integer argument", fn)
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if int64(int(n)) != n {
			return 0, fmt.Errorf("%s integer argument overflows int: %d", fn, n)
		}
		return int(n), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := v.Uint()
		if u > uint64(math.MaxInt) {
			return 0, fmt.Errorf("%s integer argument overflows int: %d", fn, u)
		}
		return int(u), nil
	default:
		return 0, fmt.Errorf("%s expects an integer argument, got %s", fn, v.Type())
	}
}

func evalLen(v reflect.Value) (reflect.Value, error) {
	v, isNil := indirectValue(v)
	if isNil || !v.IsValid() {
		return reflect.Value{}, errors.New("len of nil pointer")
	}
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return reflect.ValueOf(v.Len()), nil
	default:
		return reflect.Value{}, fmt.Errorf("len of type %s", v.Type())
	}
}

func evalIndex(item reflect.Value, indices []reflect.Value) (reflect.Value, error) {
	cur := indirectInterface(item)
	if !cur.IsValid() {
		return reflect.Value{}, errors.New("index of untyped nil")
	}
	for _, idx := range indices {
		var isNil bool
		cur, isNil = indirectValue(cur)
		if isNil || !cur.IsValid() {
			return reflect.Value{}, errors.New("index of nil pointer")
		}
		switch cur.Kind() {
		case reflect.Array, reflect.Slice, reflect.String:
			n, err := requireInt("index", idx)
			if err != nil {
				return reflect.Value{}, err
			}
			if n < 0 || n >= cur.Len() {
				return reflect.Value{}, fmt.Errorf("index out of range: %d", n)
			}
			cur = cur.Index(n)
		case reflect.Map:
			key, err := prepareMapKey(idx, cur.Type().Key())
			if err != nil {
				return reflect.Value{}, err
			}
			elem := cur.MapIndex(key)
			if !elem.IsValid() {
				cur = reflect.Zero(cur.Type().Elem())
			} else {
				cur = elem
			}
		default:
			return reflect.Value{}, fmt.Errorf("can't index item of type %s", cur.Type())
		}
	}
	return cur, nil
}

func prepareMapKey(idx reflect.Value, keyType reflect.Type) (reflect.Value, error) {
	idx = indirectInterface(idx)
	if !idx.IsValid() {
		switch keyType.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			return reflect.Zero(keyType), nil
		default:
			return reflect.Value{}, fmt.Errorf("cannot assign nil to type %s", keyType)
		}
	}
	if idx.Type().AssignableTo(keyType) {
		return idx, nil
	}
	if isIntegerKind(idx.Kind()) && isIntegerKind(keyType.Kind()) {
		n, err := requireInt("index", idx)
		if err != nil {
			return reflect.Value{}, err
		}
		if n < 0 && isUnsignedKind(keyType.Kind()) {
			return reflect.Value{}, fmt.Errorf("negative index %d for unsigned key type %s", n, keyType)
		}
		return idx.Convert(keyType), nil
	}
	if idx.Kind() == reflect.String && keyType.Kind() == reflect.String {
		return idx.Convert(keyType), nil
	}
	return reflect.Value{}, fmt.Errorf("value has type %s; should be %s", idx.Type(), keyType)
}

func isIntegerKind(k reflect.Kind) bool {
	return isSignedKind(k) || isUnsignedKind(k)
}

func isSignedKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func isUnsignedKind(k reflect.Kind) bool {
	switch k {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	default:
		return false
	}
}

func evalSlice(item reflect.Value, bounds []reflect.Value) (reflect.Value, error) {
	v, isNil := indirectValue(item)
	if isNil || !v.IsValid() {
		return reflect.Value{}, errors.New("slice of nil pointer")
	}
	var maxCap int
	switch v.Kind() {
	case reflect.Array:
		if !v.CanAddr() {
			return reflect.Value{}, fmt.Errorf("cannot slice unaddressable array of type %s", v.Type())
		}
		maxCap = v.Cap()
	case reflect.Slice:
		maxCap = v.Cap()
	case reflect.String:
		if len(bounds) == 3 {
			return reflect.Value{}, errors.New("cannot 3-index slice a string")
		}
		maxCap = v.Len()
	default:
		return reflect.Value{}, fmt.Errorf("can't slice item of type %s", v.Type())
	}

	idx := [3]int{0, v.Len(), maxCap}
	for i, b := range bounds {
		n, err := requireInt("slice", b)
		if err != nil {
			return reflect.Value{}, err
		}
		idx[i] = n
	}
	if len(bounds) == 3 {
		if idx[0] < 0 || idx[0] > idx[1] || idx[1] > idx[2] || idx[2] > maxCap {
			return reflect.Value{}, fmt.Errorf("slice index out of range: %d:%d:%d", idx[0], idx[1], idx[2])
		}
		return v.Slice3(idx[0], idx[1], idx[2]), nil
	}
	if idx[0] < 0 || idx[0] > idx[1] || idx[1] > maxCap {
		return reflect.Value{}, fmt.Errorf("slice index out of range: %d:%d", idx[0], idx[1])
	}
	return v.Slice(idx[0], idx[1]), nil
}

func isTemplateTruthy(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() > 0
	case reflect.Bool:
		return v.Bool()
	case reflect.Complex64, reflect.Complex128:
		return v.Complex() != 0
	case reflect.Chan, reflect.Func, reflect.Pointer, reflect.UnsafePointer:
		return !v.IsNil()
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return isTemplateTruthy(v.Elem())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() != 0
	case reflect.Float32, reflect.Float64:
		return v.Float() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() != 0
	case reflect.Struct:
		return true
	default:
		return false
	}
}

type valueClass int

const (
	classInvalid valueClass = iota
	classBool
	classInt
	classUint
	classFloat
	classComplex
	classString
	classOther
)

func classifyBasic(v reflect.Value) valueClass {
	if !v.IsValid() {
		return classInvalid
	}
	switch v.Kind() {
	case reflect.Bool:
		return classBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return classInt
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return classUint
	case reflect.Float32, reflect.Float64:
		return classFloat
	case reflect.Complex64, reflect.Complex128:
		return classComplex
	case reflect.String:
		return classString
	default:
		return classOther
	}
}

func isNilValue(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func canCompareTypes(v1, v2 reflect.Value) bool {
	if !v1.IsValid() || !v2.IsValid() {
		return true
	}
	t1, t2 := v1.Type(), v2.Type()
	if t1 == t2 {
		return true
	}
	if t1.Kind() == reflect.Interface || t2.Kind() == reflect.Interface {
		return true
	}
	return false
}

func valuesEqual(a, b reflect.Value) (bool, error) {
	v1 := indirectInterface(a)
	v2 := indirectInterface(b)
	c1 := classifyBasic(v1)
	c2 := classifyBasic(v2)

	if c1 == classInvalid || c2 == classInvalid {
		return isNilValue(v1) && isNilValue(v2), nil
	}
	if c1 == classOther || c2 == classOther {
		if !canCompareTypes(v1, v2) {
			return false, fmt.Errorf("incompatible types for comparison: %s and %s", v1.Type(), v2.Type())
		}
		if isNilValue(v1) || isNilValue(v2) {
			return isNilValue(v1) == isNilValue(v2), nil
		}
		if v1.Type().Comparable() && v2.Type().Comparable() {
			return v1.Interface() == v2.Interface(), nil
		}
		return false, fmt.Errorf("non-comparable types for comparison: %s and %s", v1.Type(), v2.Type())
	}

	if c1 == c2 {
		switch c1 {
		case classBool:
			return v1.Bool() == v2.Bool(), nil
		case classInt:
			return v1.Int() == v2.Int(), nil
		case classUint:
			return v1.Uint() == v2.Uint(), nil
		case classFloat:
			return v1.Float() == v2.Float(), nil
		case classComplex:
			return v1.Complex() == v2.Complex(), nil
		case classString:
			return v1.String() == v2.String(), nil
		}
	}
	if c1 == classInt && c2 == classUint {
		return v1.Int() >= 0 && uint64(v1.Int()) == v2.Uint(), nil
	}
	if c1 == classUint && c2 == classInt {
		return v2.Int() >= 0 && v1.Uint() == uint64(v2.Int()), nil
	}
	return false, fmt.Errorf("incompatible types for comparison: %s and %s", v1.Type(), v2.Type())
}

func evalOrderedComparison(op string, a, b reflect.Value) (bool, error) {
	v1 := indirectInterface(a)
	v2 := indirectInterface(b)
	c1 := classifyBasic(v1)
	c2 := classifyBasic(v2)

	if c1 == classFloat && c2 == classFloat {
		f1, f2 := v1.Float(), v2.Float()
		// Match text/template/funcs.go: le is lt||eq, ge is !lt, gt is !le.
		switch op {
		case "lt":
			return f1 < f2, nil
		case "le":
			return f1 < f2 || f1 == f2, nil
		case "gt":
			return !(f1 < f2 || f1 == f2), nil
		default:
			return !(f1 < f2), nil
		}
	}

	var rel int
	switch {
	case c1 == classInt && c2 == classInt:
		rel = cmp.Compare(v1.Int(), v2.Int())
	case c1 == classUint && c2 == classUint:
		rel = cmp.Compare(v1.Uint(), v2.Uint())
	case c1 == classInt && c2 == classUint:
		if v1.Int() < 0 {
			rel = -1
		} else {
			rel = cmp.Compare(uint64(v1.Int()), v2.Uint())
		}
	case c1 == classUint && c2 == classInt:
		if v2.Int() < 0 {
			rel = 1
		} else {
			rel = cmp.Compare(v1.Uint(), uint64(v2.Int()))
		}
	case c1 == classString && c2 == classString:
		rel = cmp.Compare(v1.String(), v2.String())
	default:
		return false, fmt.Errorf("incompatible types for ordered comparison: %s and %s", valueTypeName(v1), valueTypeName(v2))
	}

	switch op {
	case "lt":
		return rel < 0, nil
	case "le":
		return rel <= 0, nil
	case "gt":
		return rel > 0, nil
	default:
		return rel >= 0, nil
	}
}

func valueTypeName(v reflect.Value) string {
	if !v.IsValid() {
		return "nil"
	}
	return v.Type().String()
}

func compareMapKeys(a, b reflect.Value) int {
	if lt, err := evalOrderedComparison("lt", a, b); err == nil {
		if lt {
			return -1
		}
		if gt, err := evalOrderedComparison("gt", a, b); err == nil && gt {
			return 1
		}
		return 0
	}
	return cmp.Compare(fmt.Sprint(a.Interface()), fmt.Sprint(b.Interface()))
}
