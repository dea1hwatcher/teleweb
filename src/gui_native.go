//go:build nativegui

package main

import (
	"fmt"
	"image"
	"image/color"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// Material 3 Expressive Dark Theme Tokens (Telegram Cyan & Ocean Palette)
var (
	colBg               = color.NRGBA{R: 0x10, G: 0x14, B: 0x18, A: 0xFF} // #101418 Surface
	colSurfaceLow       = color.NRGBA{R: 0x18, G: 0x1C, B: 0x20, A: 0xFF} // #181c20 Surface Container Low
	colCard             = color.NRGBA{R: 0x1C, G: 0x20, B: 0x24, A: 0xFF} // #1c2024 Surface Container (Card)
	colCardHigh         = color.NRGBA{R: 0x26, G: 0x2A, B: 0x2F, A: 0xFF} // #262a2f Surface Container High
	colCardHighest      = color.NRGBA{R: 0x31, G: 0x35, B: 0x3A, A: 0xFF} // #31353a Surface Container Highest
	colTerminalBg       = color.NRGBA{R: 0x0B, G: 0x0F, B: 0x12, A: 0xFF} // #0b0f12 Lowest Terminal
	colPrimary          = color.NRGBA{R: 0x7E, G: 0xD0, B: 0xFF, A: 0xFF} // #7ed0ff Telegram Cyan
	colOnPrimary        = color.NRGBA{R: 0x00, G: 0x34, B: 0x4F, A: 0xFF} // #00344f Deep Ocean Navy
	colPrimaryContainer = color.NRGBA{R: 0x00, G: 0x4C, B: 0x70, A: 0xFF} // #004c70 Primary Container
	colOnPrimaryCont    = color.NRGBA{R: 0xC6, G: 0xE7, B: 0xFF, A: 0xFF} // #c6e7ff On Primary Container
	colSecondary        = color.NRGBA{R: 0xB6, G: 0xC9, B: 0xD8, A: 0xFF} // #b6c9d8 Secondary
	colText             = color.NRGBA{R: 0xE0, G: 0xE2, B: 0xE8, A: 0xFF} // #e0e2e8 On Surface Text
	colTextMuted        = color.NRGBA{R: 0x90, G: 0x98, B: 0xA2, A: 0xFF} // #9098a2 Subtitle / Hint
	colOutline          = color.NRGBA{R: 0x41, G: 0x47, B: 0x4D, A: 0xFF} // #41474d Outline Variant
	colSuccess          = color.NRGBA{R: 0x85, G: 0xD9, B: 0x96, A: 0xFF} // #85d996 Active Mint Green
	colSuccessContainer = color.NRGBA{R: 0x00, G: 0x53, B: 0x22, A: 0xFF} // #005322 Active Pill Background
	colError            = color.NRGBA{R: 0xFF, G: 0xB4, B: 0xAB, A: 0xFF} // #ffb4ab Warning Coral Red
	colErrorContainer   = color.NRGBA{R: 0x93, G: 0x00, B: 0x0A, A: 0xFF} // #93000a Stopped Pill Background
)

type guiTab int

const (
	tabStatus guiTab = iota
	tabRouting
	tabLogs
)

type guiState struct {
	mu        sync.Mutex
	themeOnce sync.Once
	st        Status
	busy      bool
	activeTab guiTab

	// Navigation
	tabStatusBtn    widget.Clickable
	tabRoutingBtn   widget.Clickable
	tabLogsBtn      widget.Clickable
	refreshBtn      widget.Clickable
	trayMinimizeBtn widget.Clickable

	// Status Actions
	heroToggleBtn  widget.Clickable
	heroRestartBtn widget.Clickable
	heroElevateBtn widget.Clickable
	openWebUIBtn   widget.Clickable

	// Routing & Settings
	settingsInitialized bool
	swCFPriority        widget.Bool
	swCFBalance         widget.Bool
	swDoH               widget.Bool
	swH2Media           widget.Bool
	swForceTestDC       widget.Bool
	swDC203             widget.Bool

	edCustomDomain widget.Editor
	edCustomWorker widget.Editor
	edDCOverrides  widget.Editor

	poolBtn0 widget.Clickable
	poolBtn1 widget.Clickable
	poolBtn2 widget.Clickable
	poolBtn4 widget.Clickable
	poolSize int

	saveConfigBtn widget.Clickable
	saveMsg       string
	saveMsgTime   time.Time

	// Logs Tab
	clearLogsBtn widget.Clickable
	logsList     layout.List
	contentList  layout.List
}

// cmdGui opens the native Material 3 desktop dashboard window. This is the
// double-click entry point on Windows (built with -tags nativegui).
func cmdGui(_ string) {
	ensureDir()
	startSignalLogger()

	cleanup, ok := acquireSingleInstance()
	if !ok {
		// Existing instance was brought to foreground
		return
	}
	defer cleanup()

	trayCleanup := setupSystemTray(
		"TeleWEB",
		func() {
			st := status()
			target := !st.Running
			_, _ = apiDispatch(apiRequest{Cmd: "set", Enabled: &target})
		},
		func() {
			openInBrowser("http://127.0.0.1:17842")
		},
		func() {
			stopServer()
			os.Exit(0)
		},
	)
	defer trayCleanup()

	go func() {
		w := new(app.Window)
		w.Option(
			app.Title("TeleWEB"),
			app.Size(unit.Dp(1080), unit.Dp(720)),
			app.MinSize(unit.Dp(860), unit.Dp(580)),
		)
		if err := guiLoop(w); err != nil {
			logf("gui: %v", err)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}

func guiLoop(w *app.Window) error {
	th := material.NewTheme()
	th.Palette = material.Palette{
		Bg:         colBg,
		Fg:         colText,
		ContrastBg: colPrimary,
		ContrastFg: colOnPrimary,
	}

	st := &guiState{
		activeTab: tabStatus,
		poolSize:  2,
	}
	st.logsList.Axis = layout.Vertical
	st.logsList.ScrollToEnd = true
	st.contentList.Axis = layout.Vertical

	st.edCustomDomain.SingleLine = true
	st.edCustomWorker.SingleLine = true
	st.edDCOverrides.SingleLine = true

	st.refresh()

	stop := make(chan struct{})
	defer close(stop)
	go guiPollLoop(w, st, stop)

	var ops op.Ops
	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case *app.ClosingEvent:
			if runtime.GOOS == "windows" {
				e.Abort()
				hideMainWindow()
			}
		case app.FrameEvent:
			st.themeOnce.Do(func() {
				applyWindowsDarkTheme("TeleWEB")
			})
			gtx := app.NewContext(&ops, e)
			handleGuiEvents(w, st, gtx)
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
			if runtime.GOOS == "windows" {
				tip := "TeleWEB: Остановлен"
				if st.st.Running {
					tip = "TeleWEB: Активен (WinDivert)"
					if !st.st.Redirector {
						tip = "TeleWEB: Активен (SOCKS / WSS)"
					}
				}
				updateSystemTray(st.st.Running, tip)
			}
		}
	}
}

// refresh calls apiDispatch directly in-process, without spawning child processes.
func (st *guiState) refresh() {
	st.mu.Lock()
	defer st.mu.Unlock()

	res, err := apiDispatch(apiRequest{Cmd: "status"})
	if err != nil {
		return
	}
	s, ok := res.(Status)
	if !ok {
		return
	}
	st.st = s

	if !st.settingsInitialized {
		st.settingsInitialized = true
		st.swCFPriority.Value = s.CFPriority
		st.swCFBalance.Value = s.CFBalance
		st.swDoH.Value = s.DoHEnabled
		st.swH2Media.Value = s.H2MediaEnabled
		st.swForceTestDC.Value = s.ForceTestDC
		st.swDC203.Value = s.DC203DirectTCP
		st.edCustomDomain.SetText(s.CustomCFDomain)
		st.edCustomWorker.SetText(s.CustomCFWorker)
		st.edDCOverrides.SetText(s.DCOverrides)
		st.poolSize = s.PoolSize
	}
}

func handleGuiEvents(w *app.Window, st *guiState, gtx layout.Context) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Navigation tabs
	if st.tabStatusBtn.Clicked(gtx) {
		st.activeTab = tabStatus
		w.Invalidate()
	}
	if st.tabRoutingBtn.Clicked(gtx) {
		st.activeTab = tabRouting
		w.Invalidate()
	}
	if st.tabLogsBtn.Clicked(gtx) {
		st.activeTab = tabLogs
		w.Invalidate()
	}
	if st.refreshBtn.Clicked(gtx) {
		go func() {
			st.refresh()
			w.Invalidate()
		}()
	}
	if st.trayMinimizeBtn.Clicked(gtx) {
		hideMainWindow()
	}

	// Hero Start / Stop Toggle
	if st.heroToggleBtn.Clicked(gtx) && !st.busy {
		target := !st.st.Running
		st.busy = true
		w.Invalidate()
		go func() {
			_, _ = apiDispatch(apiRequest{Cmd: "set", Enabled: &target})
			time.Sleep(300 * time.Millisecond)
			st.refresh()
			st.mu.Lock()
			st.busy = false
			st.mu.Unlock()
			w.Invalidate()
		}()
	}

	// Hero Restart (Resume / Reapply WinDivert)
	if st.heroRestartBtn.Clicked(gtx) && !st.busy {
		st.busy = true
		w.Invalidate()
		go func() {
			_, _ = apiDispatch(apiRequest{Cmd: "resume"})
			time.Sleep(250 * time.Millisecond)
			st.refresh()
			st.mu.Lock()
			st.busy = false
			st.mu.Unlock()
			w.Invalidate()
		}()
	}

	// Open WebUI in browser
	if st.openWebUIBtn.Clicked(gtx) {
		go openInBrowser("http://127.0.0.1:17842")
	}

	// UAC Elevation
	if st.heroElevateBtn.Clicked(gtx) {
		if err := restartElevated(); err != nil {
			logf("gui: elevate: %v", err)
		}
	}

	// Pool size selectors
	if st.poolBtn0.Clicked(gtx) {
		st.poolSize = 0
		w.Invalidate()
	}
	if st.poolBtn1.Clicked(gtx) {
		st.poolSize = 1
		w.Invalidate()
	}
	if st.poolBtn2.Clicked(gtx) {
		st.poolSize = 2
		w.Invalidate()
	}
	if st.poolBtn4.Clicked(gtx) {
		st.poolSize = 4
		w.Invalidate()
	}

	// Save Settings
	if st.saveConfigBtn.Clicked(gtx) && !st.busy {
		st.busy = true
		w.Invalidate()
		cfPri := st.swCFPriority.Value
		cfBal := st.swCFBalance.Value
		doh := st.swDoH.Value
		h2m := st.swH2Media.Value
		tdc := st.swForceTestDC.Value
		dc203 := st.swDC203.Value
		cDom := strings.TrimSpace(st.edCustomDomain.Text())
		cWork := strings.TrimSpace(st.edCustomWorker.Text())
		dcOvr := strings.TrimSpace(st.edDCOverrides.Text())
		pSize := st.poolSize

		go func() {
			_, err := apiDispatch(apiRequest{
				Cmd:            "set",
				CFPriority:     &cfPri,
				CFBalance:      &cfBal,
				DoHEnabled:     &doh,
				H2MediaEnabled: &h2m,
				ForceTestDC:    &tdc,
				DC203DirectTCP: &dc203,
				CustomCFDomain: &cDom,
				CustomCFWorker: &cWork,
				DCOverrides:    &dcOvr,
				PoolSize:       &pSize,
			})
			st.mu.Lock()
			st.busy = false
			if err != nil {
				st.saveMsg = "Ошибка: " + err.Error()
			} else {
				st.saveMsg = "Настройки успешно сохранены!"
			}
			st.saveMsgTime = time.Now()
			st.mu.Unlock()
			st.refresh()
			w.Invalidate()
		}()
	}

	// Clear Logs
	if st.clearLogsBtn.Clicked(gtx) {
		go func() {
			_, _ = apiDispatch(apiRequest{Cmd: "clearlogs"})
			st.refresh()
			w.Invalidate()
		}()
	}
}

func guiLayout(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	// Fill window background with Material 3 dark surface
	paint.Fill(gtx.Ops, colBg)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Top App Bar
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return renderAppBar(st, gtx, th)
		}),
		// Active Tab Content
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			st.mu.Lock()
			tab := st.activeTab
			st.mu.Unlock()

			switch tab {
			case tabStatus:
				return renderStatusTab(st, gtx, th)
			case tabRouting:
				return renderRoutingTab(st, gtx, th)
			case tabLogs:
				return renderLogsTab(st, gtx, th)
			default:
				return renderStatusTab(st, gtx, th)
			}
		}),
	)
}

func renderAppBar(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, colSurfaceLow, clip.Rect{Max: gtx.Constraints.Min}.Op())
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(20), Right: unit.Dp(20)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					// Brand Title + Status Badge
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								title := material.H5(th, "TeleWEB")
								title.Color = colPrimary
								title.Font.Weight = font.Bold
								return title.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								st.mu.Lock()
								running := st.st.Running
								redirector := st.st.Redirector
								st.mu.Unlock()

								badgeBg := colErrorContainer
								badgeCol := colError
								badgeText := "● Остановлен"
								if running && redirector {
									badgeBg = colSuccessContainer
									badgeCol = colSuccess
									badgeText = "● Активен (WinDivert)"
								} else if running {
									badgeBg = colPrimaryContainer
									badgeCol = colPrimary
									badgeText = "● Работает (без драйвера)"
								}

								return card(gtx, badgeBg, 12, func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Top: unit.Dp(3), Bottom: unit.Dp(3), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										lbl := material.Caption(th, badgeText)
										lbl.Color = badgeCol
										lbl.Font.Weight = font.Medium
										return lbl.Layout(gtx)
									})
								})
							}),
						)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
					// Navigation Tabs
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						st.mu.Lock()
						active := st.activeTab
						st.mu.Unlock()

						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTabBtn(gtx, th, &st.tabStatusBtn, "Состояние", active == tabStatus)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTabBtn(gtx, th, &st.tabRoutingBtn, "Маршрутизация", active == tabRouting)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTabBtn(gtx, th, &st.tabLogsBtn, "Журнал", active == tabLogs)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderIconButton(gtx, th, &st.refreshBtn, "↻")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderIconButton(gtx, th, &st.trayMinimizeBtn, "⤓")
							}),
						)
					}),
				)
			})
		}),
	)
}

func renderTabBtn(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, selected bool) layout.Dimensions {
	bg := colCardHigh
	fg := colTextMuted
	if selected {
		bg = colPrimaryContainer
		fg = colOnPrimaryCont
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return card(gtx, bg, 18, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, label)
				lbl.Color = fg
				if selected {
					lbl.Font.Weight = font.SemiBold
				}
				return lbl.Layout(gtx)
			})
		})
	})
}

func renderIconButton(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return card(gtx, colCardHigh, 16, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(th, label)
				lbl.Color = colPrimary
				return lbl.Layout(gtx)
			})
		})
	})
}

// ============================================================================
// TAB 1: СОСТОЯНИЕ (Control / Status)
// ============================================================================

func renderStatusTab(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	s := st.st
	busy := st.busy
	st.mu.Unlock()

	return layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(16), Left: unit.Dp(20), Right: unit.Dp(20)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		widgets := []layout.Widget{
			// 1. Hero Card
			func(gtx layout.Context) layout.Dimensions {
				return renderHeroCard(st, gtx, th, s, busy)
			},
			// Spacer
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// 2. DC Matrix Card
			func(gtx layout.Context) layout.Dimensions {
				return renderDCMatrixCard(gtx, th, s)
			},
			// Spacer
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// 3. Service & Network Endpoints Card
			func(gtx layout.Context) layout.Dimensions {
				return renderServiceInfoCard(st, gtx, th, s)
			},
		}

		return st.contentList.Layout(gtx, len(widgets), func(gtx layout.Context, i int) layout.Dimensions {
			return widgets[i](gtx)
		})
	})
}

func renderHeroCard(st *guiState, gtx layout.Context, th *material.Theme, s Status, busy bool) layout.Dimensions {
	return card(gtx, colCard, 16, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				// Header row: status titles + action buttons
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									stateText := "Транспорт активен"
									stateColor := colPrimary
									if !s.Running {
										stateText = "Транспорт остановлен"
										stateColor = colTextMuted
									}
									lbl := material.H6(th, stateText)
									lbl.Color = stateColor
									lbl.Font.Weight = font.Bold
									return lbl.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									sub := "DC1–DC5 через WebSocket · Прозрачный перехват (WinDivert)"
									if !s.Running {
										sub = "Нажмите «Запустить» для перехвата и туннелирования Telegram"
									}
									lbl := material.Body2(th, sub)
									lbl.Color = colTextMuted
									return lbl.Layout(gtx)
								}),
							)
						}),
						// Primary Start/Stop Button
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btnText := "Запустить"
							btnBg := colPrimary
							btnFg := colOnPrimary
							if s.Running {
								btnText = "Остановить"
								btnBg = colErrorContainer
								btnFg = colError
							}
							if busy {
								btnText = "Секунду…"
							}

							return st.heroToggleBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return card(gtx, btnBg, 20, func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body1(th, btnText)
										lbl.Color = btnFg
										lbl.Font.Weight = font.Bold
										return lbl.Layout(gtx)
									})
								})
							})
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						// Restart / Reapply Button
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return st.heroRestartBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return card(gtx, colCardHigh, 20, func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body2(th, "Перезапустить")
										lbl.Color = colText
										return lbl.Layout(gtx)
									})
								})
							})
						}),
					)
				}),
				// UAC Elevation Banner (Windows without Admin rights)
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if runtime.GOOS != "windows" || isElevated() {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return card(gtx, colCardHighest, 12, func(gtx layout.Context) layout.Dimensions {
							return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Body2(th, "Требуются права Администратора для сетевого драйвера WinDivert")
												lbl.Color = colText
												lbl.Font.Weight = font.Bold
												return lbl.Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Caption(th, "Без повышения прав доступен только SOCKS5 режим или служба Windows")
												lbl.Color = colTextMuted
												return lbl.Layout(gtx)
											}),
										)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return st.heroElevateBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return card(gtx, colPrimary, 16, func(gtx layout.Context) layout.Dimensions {
												return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
													lbl := material.Caption(th, "Запустить от Администратора")
													lbl.Color = colOnPrimary
													lbl.Font.Weight = font.Bold
													return lbl.Layout(gtx)
												})
											})
										})
									}),
								)
							})
						})
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
				// Stats Grid (6 stat cards)
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					traffic := fmt.Sprintf("↑%s  ↓%s", formatBytes(s.TrafficUpBytes), formatBytes(s.TrafficDownBytes))
					pop := s.LastCFPoP
					if pop == "" {
						pop = "—"
					}
					metrics := []struct{ label, val string }{
						{"Сессии", strconv.FormatInt(s.Active, 10)},
						{"WS-сессии", strconv.FormatInt(s.WS, 10)},
						{"Память RSS", formatBytes(s.MemNowBytes)},
						{"Uptime", formatUptime(s.Uptime)},
						{"Трафик", traffic},
						{"CF PoP", pop},
					}

					children := make([]layout.FlexChild, 0, len(metrics))
					for _, m := range metrics {
						item := m
						children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return card(gtx, colCardHigh, 12, func(gtx layout.Context) layout.Dimensions {
									return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Caption(th, item.label)
												lbl.Color = colTextMuted
												return lbl.Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Body1(th, item.val)
												lbl.Color = colText
												lbl.Font.Weight = font.Bold
												return lbl.Layout(gtx)
											}),
										)
									})
								})
							})
						}))
					}
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
				}),
			)
		})
	})
}

func renderDCMatrixCard(gtx layout.Context, th *material.Theme, s Status) layout.Dimensions {
	cities := map[string]string{
		"1": "Майами (США)",
		"2": "Амстердам (EU)",
		"3": "Майами (США)",
		"4": "Амстердам (EU)",
		"5": "Сингапур (Азия)",
	}

	return card(gtx, colCard, 16, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body1(th, "Датацентры Telegram (DC Matrix)")
					lbl.Color = colText
					lbl.Font.Weight = font.Bold
					return lbl.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					dcKeys := []string{"1", "2", "3", "4", "5"}
					children := make([]layout.FlexChild, 0, 5)

					for _, dc := range dcKeys {
						dcNum := dc
						count := s.DC[dcNum]
						city := cities[dcNum]

						children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								bg := colCardHigh
								if count > 0 {
									bg = colPrimaryContainer
								}

								return card(gtx, bg, 12, func(gtx layout.Context) layout.Dimensions {
									return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.H6(th, "DC"+dcNum)
												lbl.Color = colPrimary
												lbl.Font.Weight = font.Bold
												return lbl.Layout(gtx)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Caption(th, city)
												lbl.Color = colTextMuted
												return lbl.Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												valCol := colTextMuted
												if count > 0 {
													valCol = colSuccess
												}
												lbl := material.H5(th, strconv.Itoa(count))
												lbl.Color = valCol
												lbl.Font.Weight = font.Bold
												return lbl.Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												tagText := "Direct"
												tagBg := colCardHighest
												tagFg := colTextMuted
												if s.Running {
													tagText = "WSS"
													tagBg = colPrimaryContainer
													tagFg = colOnPrimaryCont
												}
												return card(gtx, tagBg, 8, func(gtx layout.Context) layout.Dimensions {
													return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														tLbl := material.Caption(th, tagText)
														tLbl.Color = tagFg
														tLbl.Font.Weight = font.SemiBold
														return tLbl.Layout(gtx)
													})
												})
											}),
										)
									})
								})
							})
						}))
					}
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				// Summary bar
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderMetaChip(gtx, th, "Пул WSS", strconv.Itoa(s.PoolSize))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderMetaChip(gtx, th, "Попадания в пул", strconv.FormatInt(s.PoolHits, 10))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderMetaChip(gtx, th, "Ошибки перехвата", strconv.FormatInt(s.Fail, 10))
						}),
					)
				}),
			)
		})
	})
}

func renderMetaChip(gtx layout.Context, th *material.Theme, label, val string) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(th, label+": ")
			lbl.Color = colTextMuted
			return lbl.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(th, val)
			lbl.Color = colText
			lbl.Font.Weight = font.Bold
			return lbl.Layout(gtx)
		}),
	)
}

func renderServiceInfoCard(st *guiState, gtx layout.Context, th *material.Theme, s Status) layout.Dimensions {
	return card(gtx, colCard, 16, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body1(th, "Интерфейсы и Службы")
							lbl.Color = colText
							lbl.Font.Weight = font.Bold
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							socksPort := strconv.Itoa(s.Port)
							if socksPort == "0" {
								socksPort = "1080"
							}
							info := fmt.Sprintf("Локальный SOCKS5: 127.0.0.1:%s  •  WebUI: http://127.0.0.1:17842", socksPort)
							lbl := material.Body2(th, info)
							lbl.Color = colTextMuted
							return lbl.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return st.openWebUIBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return card(gtx, colCardHigh, 18, func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body2(th, "Открыть WebUI в браузере ↗")
								lbl.Color = colPrimary
								lbl.Font.Weight = font.SemiBold
								return lbl.Layout(gtx)
							})
						})
					})
				}),
			)
		})
	})
}

// ============================================================================
// TAB 2: МАРШРУТИЗАЦИЯ (Routing / Settings)
// ============================================================================

func renderRoutingTab(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	busy := st.busy
	saveMsg := st.saveMsg
	saveMsgTime := st.saveMsgTime
	currentPool := st.poolSize
	st.mu.Unlock()

	return layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(16), Left: unit.Dp(20), Right: unit.Dp(20)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		items := []layout.Widget{
			// Card 1: WebSocket & Cloudflare Toggles
			func(gtx layout.Context) layout.Dimensions {
				return card(gtx, colCard, 16, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Режим WebSocket & Cloudflare")
								lbl.Color = colPrimary
								lbl.Font.Weight = font.Bold
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swCFPriority, "Форсировать Cloudflare (CF Priority)", "Приоритетная маршрутизация всех Telegram DC через WSS")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swCFBalance, "Балансировка доменов (CF Balance)", "Распределение подключений по пулу доступных доменов Cloudflare")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swDoH, "Защищенный DNS (Multi-DoH гонка)", "Параллельная резолвация доменов через Cloudflare, Google и Quad9")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swH2Media, "HTTP/2 ускорение медиа (CF H2)", "Мультиплексирование загрузки фото и видео через HTTP/2 соединения")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swForceTestDC, "Тестовые датацентры (Test DC)", "Перехват и перенаправление тестовых серверов Telegram (149.154.175.10)")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderSwitchRow(gtx, th, &st.swDC203, "Прямой TCP-путь для CDN203", "Прямой маршрут без WSS для CDN-кэша медиафайлов")
							}),
						)
					})
				})
			},
			// Spacer
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// Card 2: Fine-Tuning Address Inputs & Socket Pool
			func(gtx layout.Context) layout.Dimensions {
				return card(gtx, colCard, 16, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Тонкая настройка адресов и пула")
								lbl.Color = colPrimary
								lbl.Font.Weight = font.Bold
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTextInput(gtx, th, &st.edCustomDomain, "например: my-worker.example.com", "Свой Cloudflare-домен (Фронтинг)")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTextInput(gtx, th, &st.edCustomWorker, "например: my-worker.username.workers.dev", "Шлюз Cloudflare Worker (cloudflare:sockets)")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderTextInput(gtx, th, &st.edDCOverrides, "1:149.154.175.50, 2:149.154.167.220", "Ручные IP для DC (опционально)")
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
							// Pool size selector
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Caption(th, "Пул предпрогретых WSS-сокетов")
										lbl.Color = colPrimary
										return lbl.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return renderPoolOption(gtx, th, &st.poolBtn0, "Отключен (0)", currentPool == 0)
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return renderPoolOption(gtx, th, &st.poolBtn1, "Эконом (1)", currentPool == 1)
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return renderPoolOption(gtx, th, &st.poolBtn2, "Стандарт (2)", currentPool == 2)
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return renderPoolOption(gtx, th, &st.poolBtn4, "Максимум (4)", currentPool == 4)
											}),
										)
									}),
								)
							}),
						)
					})
				})
			},
			// Spacer
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// Save Action Button
			func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btnText := "Сохранить настройки"
						if busy {
							btnText = "Сохранение…"
						}
						return st.saveConfigBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return card(gtx, colPrimary, 20, func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(32), Right: unit.Dp(32)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body1(th, btnText)
									lbl.Color = colOnPrimary
									lbl.Font.Weight = font.Bold
									return lbl.Layout(gtx)
								})
							})
						})
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if saveMsg != "" && time.Since(saveMsgTime) < 4*time.Second {
							msgColor := colSuccess
							if strings.HasPrefix(saveMsg, "Ошибка") {
								msgColor = colError
							}
							lbl := material.Body2(th, saveMsg)
							lbl.Color = msgColor
							lbl.Font.Weight = font.Medium
							return lbl.Layout(gtx)
						}
						return layout.Dimensions{}
					}),
				)
			},
		}

		return st.contentList.Layout(gtx, len(items), func(gtx layout.Context, i int) layout.Dimensions {
			return items[i](gtx)
		})
	})
}

func renderSwitchRow(gtx layout.Context, th *material.Theme, sw *widget.Bool, title, subtitle string) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, title)
					lbl.Color = colText
					lbl.Font.Weight = font.Medium
					return lbl.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Caption(th, subtitle)
					lbl.Color = colTextMuted
					return lbl.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			s := material.Switch(th, sw, "")
			s.Color.Enabled = colPrimary
			s.Color.Disabled = colCardHighest
			s.Color.Track = colPrimaryContainer
			return s.Layout(gtx)
		}),
	)
}

func renderTextInput(gtx layout.Context, th *material.Theme, ed *widget.Editor, hint, label string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(th, label)
			lbl.Color = colPrimary
			return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, lbl.Layout)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return card(gtx, colCardHigh, 10, func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					editor := material.Editor(th, ed, hint)
					editor.Color = colText
					editor.HintColor = colTextMuted
					return editor.Layout(gtx)
				})
			})
		}),
	)
}

func renderPoolOption(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, selected bool) layout.Dimensions {
	bg := colCardHigh
	fg := colTextMuted
	if selected {
		bg = colPrimaryContainer
		fg = colOnPrimaryCont
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return card(gtx, bg, 10, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(6), Right: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(th, label)
				lbl.Color = fg
				lbl.Alignment = text.Middle
				if selected {
					lbl.Font.Weight = font.Bold
				}
				return lbl.Layout(gtx)
			})
		})
	})
}

// ============================================================================
// TAB 3: ЖУРНАЛ (Logs)
// ============================================================================

func renderLogsTab(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	logText := st.st.Log
	st.mu.Unlock()

	lines := strings.Split(strings.TrimRight(logText, "\r\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{"Журнал пуст (служба не записывала событий)"}
	}

	return layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(16), Left: unit.Dp(20), Right: unit.Dp(20)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Logs Action Header
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Body1(th, fmt.Sprintf("Журнал службы (%d строк)", len(lines)))
						lbl.Color = colText
						lbl.Font.Weight = font.Bold
						return lbl.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return st.clearLogsBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return card(gtx, colCardHigh, 16, func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body2(th, "Очистить журнал")
									lbl.Color = colError
									return lbl.Layout(gtx)
								})
							})
						})
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			// Terminal View
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, colTerminalBg, 12, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return st.logsList.Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
							line := lines[i]
							lineColor := colTextMuted

							lower := strings.ToLower(line)
							if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "fatal") {
								lineColor = colError
							} else if strings.Contains(lower, "active") || strings.Contains(lower, "started") || strings.Contains(lower, "listening") {
								lineColor = colSuccess
							} else if strings.Contains(lower, "wss") || strings.Contains(lower, "dc") {
								lineColor = colPrimary
							}

							return layout.Inset{Bottom: unit.Dp(2)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								lbl := material.Caption(th, line)
								lbl.Color = lineColor
								lbl.Font.Typeface = font.Typeface("Consolas, monospace")
								return lbl.Layout(gtx)
							})
						})
					})
				})
			}),
		)
	})
}

// card draws a container with rounded corners and uniform background.
func card(gtx layout.Context, bg color.NRGBA, radius int, content layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			rr := clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, radius)
			paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(content),
	)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d Б", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatUptime(sec int64) string {
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
