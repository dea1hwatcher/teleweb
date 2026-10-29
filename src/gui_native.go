//go:build nativegui

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// cmdGui opens the native horizontal dashboard window. This is the desktop
// double-click entry point (built with -tags nativegui).
func cmdGui(_ string) {
	ensureDir()
	startSignalLogger()
	go func() {
		w := new(app.Window)
		w.Option(app.Title("TeleWEB"), app.Size(unit.Dp(1120), unit.Dp(680)))
		if err := guiLoop(w); err != nil {
			logf("gui: %v", err)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}

type guiState struct {
	mu   sync.Mutex
	st   Status
	busy bool
}

var guiStartBtn = new(widget.Clickable)
var guiStopBtn = new(widget.Clickable)

func guiLoop(w *app.Window) error {
	th := material.NewTheme()
	var ops op.Ops
	st := &guiState{}
	st.refresh()
	stop := make(chan struct{})
	defer close(stop)
	go guiPollLoop(w, st, stop)
	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if guiStartBtn.Clicked(gtx) {
				go guiToggle(w, st, true)
			}
			if guiStopBtn.Clicked(gtx) {
				go guiToggle(w, st, false)
			}
			guiLayout(st, gtx, th)
			e.Frame(gtx.Ops)
		}
	}
}

func guiPollLoop(w *app.Window, st *guiState, stop chan struct{}) {
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			st.refresh()
			w.Invalidate()
		}
	}
}

// apiExec runs the API command in a child tgws process, mirroring the WebUI
// bridge, so the GUI shares the exact CLI semantics on every platform.
func apiExec(q apiRequest) (Status, error) {
	self, err := os.Executable()
	if err != nil {
		return Status{}, err
	}
	b, _ := json.Marshal(q)
	out, err := exec.Command(self, "api", base64.StdEncoding.EncodeToString(b)).Output()
	if err != nil && len(out) == 0 {
		return Status{}, err
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Data  Status `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return Status{}, err
	}
	if !resp.OK {
		return Status{}, fmt.Errorf("%s", resp.Error)
	}
	return resp.Data, nil
}

func (st *guiState) refresh() {
	s, err := apiExec(apiRequest{Cmd: "status"})
	if err != nil {
		return
	}
	st.mu.Lock()
	st.st = s
	st.mu.Unlock()
}

func guiToggle(w *app.Window, st *guiState, enable bool) {
	st.mu.Lock()
	if st.busy {
		st.mu.Unlock()
		return
	}
	st.busy = true
	st.mu.Unlock()
	w.Invalidate()
	_, _ = apiExec(apiRequest{Cmd: "set", Enabled: &enable})
	time.Sleep(300 * time.Millisecond)
	st.refresh()
	st.mu.Lock()
	st.busy = false
	st.mu.Unlock()
	w.Invalidate()
}

func guiLayout(st *guiState, gtx layout.Context, th *material.Theme) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.st

	layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Header: title + transport controls.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: 12, Bottom: 12, Left: 20, Right: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						title := material.H5(th, "TeleWEB")
						title.Color = th.ContrastBg
						return title.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if s.Running {
							lbl := material.Body1(th, "Транспорт активен")
							lbl.Color = th.ContrastBg
							return lbl.Layout(gtx)
						}
						return material.Body1(th, "Транспорт остановлен").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Left: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							if s.Running {
								return material.Button(th, guiStopBtn, "Остановить").Layout(gtx)
							}
							return material.Button(th, guiStartBtn, "Запустить").Layout(gtx)
						})
					}),
				)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				// Left column: live metrics.
				layout.Flexed(0.30, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: 20, Right: 10}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						rows := []struct{ k, v string }{
							{"Состояние", guiRunState(s)},
							{"Перехват (redirector)", strconv.FormatBool(s.Redirector)},
							{"Сессии", strconv.FormatInt(s.Active, 10)},
							{"WS-сессии", strconv.FormatInt(s.WS, 10)},
							{"Ошибки", strconv.FormatInt(s.Fail, 10)},
							{"Пул сокетов", strconv.Itoa(s.PoolSize)},
							{"Трафик ↑↓", fmt.Sprintf("%d / %d Б", s.TrafficUpBytes, s.TrafficDownBytes)},
							{"Uptime", guiUptime(s.Uptime)},
							{"Порт", strconv.Itoa(s.Port)},
						}
						children := make([]layout.FlexChild, 0, len(rows))
						for _, r := range rows {
							k, v := r.k, r.v
							children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Bottom: 8}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
										layout.Flexed(0.55, func(gtx layout.Context) layout.Dimensions {
											return material.Body1(th, k).Layout(gtx)
										}),
										layout.Flexed(0.45, func(gtx layout.Context) layout.Dimensions {
											lbl := material.Body1(th, v)
											lbl.Color = th.ContrastBg
											return lbl.Layout(gtx)
										}),
									)
								})
							}))
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
					})
				}),
				// Right column: DC matrix + log tail.
				layout.Flexed(0.70, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: 10, Right: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return material.Body1(th, "Датацентры Telegram (DC Matrix)").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: 8, Bottom: 16}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return guiDCMatrix(gtx, th, s)
								})
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return material.Body2(th, guiLogTail(s.Log)).Layout(gtx)
							}),
						)
					})
				}),
			)
		}),
	)
}

func guiDCMatrix(gtx layout.Context, th *material.Theme, s Status) layout.Dimensions {
	cities := map[string]string{"1": "Майами", "2": "Амстердам", "3": "Майами", "4": "Амстердам", "5": "Сингапур"}
	children := make([]layout.FlexChild, 0, 5)
	for _, dc := range []string{"1", "2", "3", "4", "5"} {
		dcNum := dc
		children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			count := strconv.Itoa(s.DC[dcNum])
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.Body1(th, "DC"+dcNum).Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.Caption(th, cities[dcNum]).Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.H6(th, count)
					lbl.Color = th.ContrastBg
					return lbl.Layout(gtx)
				}),
			)
		}))
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
}

func guiRunState(s Status) string {
	switch {
	case s.Running && s.Redirector:
		return "активен ✅"
	case s.Running:
		return "работает (без перехвата)"
	default:
		return "остановлен"
	}
}

func guiUptime(sec int64) string {
	if sec <= 0 {
		return "—"
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	if h > 0 {
		return fmt.Sprintf("%d ч %d мин", h, m)
	}
	return fmt.Sprintf("%d мин", m)
}

func guiLogTail(log string) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > 14 {
		lines = lines[len(lines)-14:]
	}
	out := strings.Join(lines, "\n")
	if out == "" {
		return "журнал пуст"
	}
	return out
}
