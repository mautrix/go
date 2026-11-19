// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package l10n

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog/log"
)

var (
	namespacePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	idPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
	placeholderPattern = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
)

var (
	registryLock sync.Mutex
	namespaces   = map[string]*Namespace{}
	templates    = map[string]*Template{}
)

// Namespace groups the templates of one project, e.g. "bridgev2" or
// "mautrix-whatsapp". Keys only need to be unique within their namespace.
type Namespace struct {
	name string
}

// NewNamespace returns the namespace with the given name. Calling it again with
// the same name returns the same namespace, so multiple packages in one
// project can share it.
func NewNamespace(name string) *Namespace {
	if !namespacePattern.MatchString(name) {
		panic(fmt.Errorf("l10n: invalid namespace %q", name))
	}
	registryLock.Lock()
	defer registryLock.Unlock()
	ns, ok := namespaces[name]
	if !ok {
		ns = &Namespace{name: name}
		namespaces[name] = ns
	}
	return ns
}

func (ns *Namespace) Name() string {
	return ns.name
}

// Template is a registered English message with named {placeholders}.
// Templates must be declared as package-level variables so that they are
// registered at init time and included in the catalog.
type Template struct {
	key         string
	english     string
	englishOne  string
	pluralParam string
	params      []string
	comment     string
}

type Option func(*Template)

// WithComment attaches a note for translators to the template.
func WithComment(comment string) Option {
	return func(t *Template) {
		t.comment = comment
	}
}

// Define registers a template. The English text may contain {name}
// placeholders; every placeholder becomes a required parameter of Render.
// Define panics if the key is already registered.
func (ns *Namespace) Define(id, english string, opts ...Option) *Template {
	t := &Template{english: english}
	t.params = placeholders(english)
	return ns.register(id, t, opts)
}

// DefinePlural registers a template whose English text depends on the integer
// parameter countParam: one is used when it's exactly 1, other otherwise.
// Clients use countParam to select the plural form in their own language.
func (ns *Namespace) DefinePlural(id, countParam, one, other string, opts ...Option) *Template {
	t := &Template{english: other, englishOne: one, pluralParam: countParam}
	t.params = placeholders(one, other)
	if !slices.Contains(t.params, countParam) {
		t.params = append(t.params, countParam)
		slices.Sort(t.params)
	}
	return ns.register(id, t, opts)
}

func (ns *Namespace) register(id string, t *Template, opts []Option) *Template {
	if !idPattern.MatchString(id) {
		panic(fmt.Errorf("l10n: invalid template ID %q in namespace %s", id, ns.name))
	}
	t.key = ns.name + ":" + id
	for _, opt := range opts {
		opt(t)
	}
	registryLock.Lock()
	defer registryLock.Unlock()
	if _, exists := templates[t.key]; exists {
		panic(fmt.Errorf("l10n: duplicate template key %s", t.key))
	}
	templates[t.key] = t
	return t
}

func placeholders(texts ...string) []string {
	var names []string
	for _, text := range texts {
		for _, match := range placeholderPattern.FindAllStringSubmatch(text, -1) {
			if !slices.Contains(names, match[1]) {
				names = append(names, match[1])
			}
		}
	}
	slices.Sort(names)
	return names
}

func (t *Template) Key() string {
	return t.key
}

// RenderErrorHandler is called when a template is rendered with parameters that
// don't match its placeholders. Rendering still produces readable text, but the
// resulting message is unlocalized. The default handler panics inside tests and
// logs a warning otherwise.
var RenderErrorHandler = func(t *Template, err error) {
	if testing.Testing() {
		panic(err)
	}
	log.Warn().Err(err).Str("l10n_key", t.key).Msg("Failed to render localizable message")
}

// Message returns the message for a template without parameters.
func (t *Template) Message() Message {
	return t.Render(nil)
}

// Render substitutes params into the English text and returns a localizable
// message. params must contain exactly the template's placeholders, with
// string or integer values.
func (t *Template) Render(params Params) Message {
	normalized, err := t.normalizeParams(params)
	english := t.english
	if t.pluralParam != "" {
		if count, ok := normalized[t.pluralParam].(int64); ok && count == 1 {
			english = t.englishOne
		}
	}
	text := placeholderPattern.ReplaceAllStringFunc(english, func(placeholder string) string {
		name := placeholder[1 : len(placeholder)-1]
		val, ok := normalized[name]
		if !ok {
			return placeholder
		}
		return fmt.Sprint(val)
	})
	if err != nil {
		RenderErrorHandler(t, err)
		return Unlocalized(text)
	}
	return Message{Key: t.key, Text: text, Params: normalized}
}

func (t *Template) normalizeParams(params Params) (Params, error) {
	var errs []string
	var normalized Params
	if len(params) > 0 {
		normalized = make(Params, len(params))
	}
	for name, val := range params {
		if !slices.Contains(t.params, name) {
			errs = append(errs, fmt.Sprintf("unknown param %q", name))
			continue
		}
		switch typed := val.(type) {
		case string:
			normalized[name] = typed
		case int:
			normalized[name] = int64(typed)
		case int8:
			normalized[name] = int64(typed)
		case int16:
			normalized[name] = int64(typed)
		case int32:
			normalized[name] = int64(typed)
		case int64:
			normalized[name] = typed
		case uint8:
			normalized[name] = int64(typed)
		case uint16:
			normalized[name] = int64(typed)
		case uint32:
			normalized[name] = int64(typed)
		default:
			errs = append(errs, fmt.Sprintf("param %q has unsupported type %T", name, val))
			normalized[name] = fmt.Sprint(val)
		}
	}
	for _, name := range t.params {
		if _, ok := params[name]; !ok {
			errs = append(errs, fmt.Sprintf("missing param %q", name))
		}
	}
	if t.pluralParam != "" {
		if _, ok := normalized[t.pluralParam].(int64); !ok {
			errs = append(errs, fmt.Sprintf("plural param %q must be an integer", t.pluralParam))
		}
	}
	if len(errs) > 0 {
		slices.Sort(errs)
		return normalized, fmt.Errorf("l10n: invalid params for %s: %s", t.key, strings.Join(errs, ", "))
	}
	return normalized, nil
}

// CatalogEntry describes one template for translation tooling.
type CatalogEntry struct {
	Key string `json:"key"`
	// English is the English text, or the "other" plural form for plural templates.
	English string `json:"english"`
	// EnglishOne is the "one" plural form. Only set for plural templates.
	EnglishOne  string   `json:"english_one,omitempty"`
	PluralParam string   `json:"plural_param,omitempty"`
	Params      []string `json:"params,omitempty"`
	Comment     string   `json:"comment,omitempty"`
}

// Catalog returns every registered template in the namespace, sorted by key.
// Only templates in packages linked into the current binary are included.
func Catalog(namespace string) []CatalogEntry {
	registryLock.Lock()
	defer registryLock.Unlock()
	prefix := namespace + ":"
	var entries []CatalogEntry
	for key, t := range templates {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		entries = append(entries, CatalogEntry{
			Key:         t.key,
			English:     t.english,
			EnglishOne:  t.englishOne,
			PluralParam: t.pluralParam,
			Params:      t.params,
			Comment:     t.comment,
		})
	}
	slices.SortFunc(entries, func(a, b CatalogEntry) int {
		return strings.Compare(a.Key, b.Key)
	})
	return entries
}
