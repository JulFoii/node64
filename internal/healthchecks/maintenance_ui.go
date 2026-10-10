package healthchecks

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Seiten fuer Wartungsfenster.

type maintenanceData struct {
	Windows []Maintenance
	Checks  []*Check
	Names   map[string]string
	Edit    *Maintenance
	Form    map[string]string
	Error   string
	Repeats []string
}

func (m *Module) maintenanceRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /healthchecks/maintenance", page(m.pageMaintenance))
	mux.Handle("POST /healthchecks/maintenance", page(m.pageMaintenanceSave))
	mux.Handle("GET /healthchecks/maintenance/{id}/edit", page(m.pageMaintenance))
	mux.Handle("POST /healthchecks/maintenance/{id}/edit", page(m.pageMaintenanceSave))
	mux.Handle("POST /healthchecks/maintenance/{id}/delete", page(m.pageMaintenanceDelete))
}

// localInput formatiert fuer <input type="datetime-local"> in der Zeitzone des Nutzers.
func localInput(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(loc).Format("2006-01-02T15:04")
}

func (m *Module) pageMaintenance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loc := m.g.Timezone(r)
	d, err := m.maintenanceData(r)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d.Form = map[string]string{"repeat": "none", "active": "on"}
	if idStr := r.PathValue("id"); idStr != "" {
		id, _ := strconv.ParseInt(idStr, 10, 64)
		for i := range d.Windows {
			if d.Windows[i].ID == id {
				mw := d.Windows[i]
				d.Edit = &mw
				d.Form = map[string]string{"name": mw.Name, "start_at": localInput(mw.StartAt, loc), "end_at": localInput(mw.EndAt, loc), "repeat": mw.Repeat,
					"repeat_until": localInput(mw.RepeatUntil, loc), "tokens": strings.Join(mw.Tokens, ","), "active": map[bool]string{true: "on", false: ""}[mw.Active]}
			}
		}
		if d.Edit == nil {
			m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
			return
		}
	} else {
		now := time.Now().In(loc).Truncate(time.Hour).Add(time.Hour)
		d.Form["start_at"], d.Form["end_at"] = localInput(now, loc), localInput(now.Add(2*time.Hour), loc)
	}
	_ = ctx
	m.g.Render(w, r, http.StatusOK, Name+"/maintenance", "hc.maint.title", d)
}

func (m *Module) maintenanceData(r *http.Request) (maintenanceData, error) {
	ctx := r.Context()
	d := maintenanceData{Names: map[string]string{}, Repeats: []string{"none", "daily", "weekly", "monthly"}}
	var err error
	if d.Windows, err = m.st.MaintenanceList(ctx); err != nil {
		return d, err
	}
	if d.Checks, err = m.st.Checks(ctx); err != nil {
		return d, err
	}
	for _, c := range d.Checks {
		d.Names[c.Token] = c.Name
	}
	return d, nil
}

func (m *Module) pageMaintenanceSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loc := m.g.Timezone(r)
	_ = r.ParseForm()
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	toRFC := func(s string) string {
		if s == "" {
			return ""
		}
		t, err := time.ParseInLocation("2006-01-02T15:04", s, loc)
		if err != nil {
			return s
		}
		return t.Format(time.RFC3339)
	}
	active := r.PostFormValue("active") == "on"
	in := maintenanceIn{Name: v("name"), StartAt: toRFC(v("start_at")), EndAt: toRFC(v("end_at")), Repeat: v("repeat"), RepeatUntil: toRFC(v("repeat_until")), Tokens: r.PostForm["tokens"], Active: &active}
	var mw Maintenance
	edit := r.PathValue("id") != ""
	if edit {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		list, _ := m.st.MaintenanceList(ctx)
		for _, x := range list {
			if x.ID == id {
				mw = x
			}
		}
		if mw.ID == 0 {
			m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
			return
		}
	}
	err := m.maintenanceFrom(in, &mw)
	if err == nil {
		if edit {
			err = m.st.MaintenanceUpdate(ctx, &mw)
		} else {
			err = m.st.MaintenanceInsert(ctx, &mw)
		}
	}
	if err != nil {
		d, derr := m.maintenanceData(r)
		if derr != nil {
			m.fail(w, r, derr)
			return
		}
		if edit {
			d.Edit = &mw
		}
		d.Form = map[string]string{}
		for k := range r.PostForm {
			d.Form[k] = r.PostFormValue(k)
		}
		d.Form["tokens"] = strings.Join(r.PostForm["tokens"], ",")
		d.Error = err.Error()
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/maintenance", "hc.maint.title", d)
		return
	}
	m.auditText(r, map[bool]string{true: "maintenance.update", false: "maintenance.create"}[edit], mw.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/healthchecks/maintenance", http.StatusSeeOther)
}

func (m *Module) pageMaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := m.st.MaintenanceDelete(r.Context(), id); err != nil {
		m.fail(w, r, err)
		return
	}
	m.auditText(r, "maintenance.delete", strconv.FormatInt(id, 10))
	m.g.Flash(w, r, "success", m.g.T(r, "hc.maint.deleted"))
	http.Redirect(w, r, "/healthchecks/maintenance", http.StatusSeeOther)
}
