//go:build windows && nativegui

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
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// WinUI 3 Fluent Design Dark Theme Tokens
var (
	colMicaBg           = color.NRGBA{R: 0x20, G: 0x20, B: 0x20, A: 0xFF} // SolidBackgroundFillColorBase (#202020)
	colNavPaneBg        = color.NRGBA{R: 0x1A, G: 0x1A, B: 0x1A, A: 0xFF} // NavigationViewDefaultPaneBackground (#1A1A1A)
	colNavPaneActive    = color.NRGBA{R: 0x33, G: 0x36, B: 0x3D, A: 0xFF} // Active nav item fill (#33363D)
	colNavPaneHover     = color.NRGBA{R: 0x27, G: 0x2A, B: 0x30, A: 0xFF} // Hover nav item fill (#272A30)
	colCardBg           = color.NRGBA{R: 0x2B, G: 0x2B, B: 0x2B, A: 0xFF} // CardBackgroundFillColorDefault (#2B2B2B)
	colCardSecondary    = color.NRGBA{R: 0x32, G: 0x32, B: 0x32, A: 0xFF} // CardBackgroundFillColorSecondary (#323232)
	colCardStroke       = color.NRGBA{R: 0x38, G: 0x38, B: 0x38, A: 0xFF} // CardStrokeColorDefault (#383838)
	colControlBg        = color.NRGBA{R: 0x2E, G: 0x2E, B: 0x2E, A: 0xFF} // ControlFillColorDefault (#2E2E2E)
	colControlBgHover   = color.NRGBA{R: 0x38, G: 0x38, B: 0x38, A: 0xFF} // ControlFillColorSecondary
	colControlBgPressed = color.NRGBA{R: 0x27, G: 0x27, B: 0x27, A: 0xFF} // ControlFillColorTertiary
	colControlStroke    = color.NRGBA{R: 0x48, G: 0x48, B: 0x48, A: 0xFF} // ControlStrokeColorDefault (#484848)
	colDivider          = color.NRGBA{R: 0x30, G: 0x30, B: 0x30, A: 0xFF} // DividerStrokeColorDefault (#303030)
	colTerminalBg       = color.NRGBA{R: 0x16, G: 0x16, B: 0x16, A: 0xFF} // Dark Log View Container (#161616)

	// Windows 11 Accent: SystemAccentColor (Dark)
	colAccent          = color.NRGBA{R: 0x60, G: 0xCD, B: 0xFF, A: 0xFF} // #60CDFF
	colAccentLight     = color.NRGBA{R: 0x78, G: 0xD5, B: 0xFF, A: 0xFF} // #78D5FF
	colAccentDark      = color.NRGBA{R: 0x41, G: 0xB1, B: 0xE1, A: 0xFF} // #41B1E1
	colOnAccent        = color.NRGBA{R: 0x00, G: 0x27, B: 0x3F, A: 0xFF} // Contrast navy on accent (#00273F)
	colAccentContainer = color.NRGBA{R: 0x00, G: 0x3C, B: 0x5C, A: 0xFF} // #003C5C
	colOnAccentCont    = color.NRGBA{R: 0xC6, G: 0xE7, B: 0xFF, A: 0xFF} // #C6E7FF

	// Text Tokens
	colTextPrimary   = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // TextFillColorPrimary (#FFFFFF)
	colTextSecondary = color.NRGBA{R: 0xD1, G: 0xD1, B: 0xD1, A: 0xFF} // TextFillColorSecondary (#D1D1D1)
	colTextTertiary  = color.NRGBA{R: 0x8E, G: 0x8E, B: 0x8E, A: 0xFF} // TextFillColorTertiary (#8E8E8E)

	// Status Tokens
	colSuccess          = color.NRGBA{R: 0x6C, G: 0xCB, B: 0x5F, A: 0xFF} // #6CCB5F
	colSuccessContainer = color.NRGBA{R: 0x16, G: 0x38, B: 0x1C, A: 0xFF} // #16381C
	colSuccessStroke    = color.NRGBA{R: 0x2B, G: 0x59, B: 0x32, A: 0xFF} // #2B5932

	colError          = color.NRGBA{R: 0xFF, G: 0x99, B: 0xA4, A: 0xFF} // #FF99A4
	colErrorContainer = color.NRGBA{R: 0x54, G: 0x22, B: 0x28, A: 0xFF} // #542228 (Stop button fill)
	colErrorStroke    = color.NRGBA{R: 0x7E, G: 0x2D, B: 0x37, A: 0xFF} // #7E2D37 (Stop button stroke)

	colWarning          = color.NRGBA{R: 0xFC, G: 0xE1, B: 0x00, A: 0xFF} // #FCE100
	colWarningContainer = color.NRGBA{R: 0x3A, G: 0x33, B: 0x18, A: 0xFF} // #3A3318
	colWarningStroke    = color.NRGBA{R: 0x70, G: 0x5E, B: 0x00, A: 0xFF} // #705E00
)

const (
	fontSegoe = font.Typeface("Segoe UI Variable, Segoe UI, sans-serif")
	fontMono  = font.Typeface("Consolas, Segoe UI Mono, monospace")
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

// cmdGui opens the native WinUI 3 / Fluent desktop dashboard window. This is the
// double-click entry point on Windows (built with -tags nativegui).
func cmdGui(_ string) {
	ensureDir()

	cleanup, ok := acquireSingleInstance()
	if !ok {
		// Existing instance was brought to foreground
		return
	}
	trayCleanup := setupSystemTray(
		"TeleWEB",
		func() {
			st := status()
			target := !st.Running
			_, _ = apiDispatch(apiRequest{Cmd: "set", Enabled: &target})
		},
		func() {
			runShutdownHooks()
			os.Exit(0)
		},
	)

	var teardownOnce sync.Once
	teardown := func() {
		teardownOnce.Do(func() {
			stopServer()
			trayCleanup()
			cleanup()
		})
	}
	registerShutdownHook(teardown)
	defer teardown()

	startSignalLogger()

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
			runShutdownHooks()
			os.Exit(1)
		}
		runShutdownHooks()
		os.Exit(0)
	}()
	app.Main()
}

func guiLoop(w *app.Window) error {
	th := material.NewTheme()
	th.Palette = material.Palette{
		Bg:         colMicaBg,
		Fg:         colTextPrimary,
		ContrastBg: colAccent,
		ContrastFg: colOnAccent,
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

// guiLayout renders the WinUI 3 Navigation View with a sidebar and content frame.
func guiLayout(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	// Base Mica dark background
	paint.Fill(gtx.Ops, colMicaBg)

	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		// Left Navigation Pane (WinUI 3 NavigationView)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Dp(unit.Dp(230))
			gtx.Constraints.Max.X = gtx.Dp(unit.Dp(230))
			return renderNavPane(st, gtx, th)
		}),
		// 1px Vertical Separator
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, colDivider, clip.Rect{Max: image.Pt(gtx.Dp(unit.Dp(1)), gtx.Constraints.Max.Y)}.Op())
			return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(1)), gtx.Constraints.Max.Y)}
		}),
		// Content Area
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			st.mu.Lock()
			tab := st.activeTab
			st.mu.Unlock()

			switch tab {
			case tabStatus:
				return renderStatusPage(st, gtx, th)
			case tabRouting:
				return renderRoutingPage(st, gtx, th)
			case tabLogs:
				return renderLogsPage(st, gtx, th)
			default:
				return renderStatusPage(st, gtx, th)
			}
		}),
	)
}

// ============================================================================
// NAVIGATION PANE (WinUI 3 NavigationView)
// ============================================================================

func renderNavPane(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	paint.FillShape(gtx.Ops, colNavPaneBg, clip.Rect{Max: gtx.Constraints.Max}.Op())

	return layout.Inset{Top: unit.Dp(18), Bottom: unit.Dp(16), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// App Header
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: unit.Dp(12), Bottom: unit.Dp(18)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return fluentCard(gtx, colAccent, color.NRGBA{}, 4, func(gtx layout.Context) layout.Dimensions {
										return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(16)), gtx.Dp(unit.Dp(16)))}
									})
								}),
								layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body1(th, "TeleWEB")
									lbl.Color = colTextPrimary
									lbl.Font.Weight = font.Bold
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
							)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(th, "WSS Transport · Windows")
							lbl.Color = colTextTertiary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				})
			}),
			// Nav items
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				st.mu.Lock()
				active := st.activeTab
				st.mu.Unlock()

				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return renderNavItem(gtx, th, &st.tabStatusBtn, "⊞", "Состояние", active == tabStatus)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return renderNavItem(gtx, th, &st.tabRoutingBtn, "⎕", "Маршрутизация", active == tabRouting)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return renderNavItem(gtx, th, &st.tabLogsBtn, "≣", "Журнал событий", active == tabLogs)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
			// Secondary actions (Status refresh & Tray minimize)
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return renderNavFooterBtn(gtx, th, &st.refreshBtn, "↻", "Обновить статус")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return renderNavFooterBtn(gtx, th, &st.trayMinimizeBtn, "🗕", "Свернуть в трей")
					}),
				)
			}),
			// Flexible spacer filling remainder of sidebar
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Dimensions{}
			}),
		)
	})
}

func renderNavItem(gtx layout.Context, th *material.Theme, btn *widget.Clickable, icon, label string, selected bool) layout.Dimensions {
	bg := color.NRGBA{}
	fg := colTextSecondary
	if selected {
		bg = colNavPaneActive
		fg = colTextPrimary
	} else if btn.Hovered() {
		bg = colNavPaneHover
	}

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			// Background
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				if bg.A > 0 {
					rr := clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, 6)
					paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
				}
				return layout.Dimensions{Size: gtx.Constraints.Min}
			}),
			// Selected Left Vertical Accent Pill (WinUI 3 NavigationView indicator)
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				if !selected {
					return layout.Dimensions{}
				}
				pillW := gtx.Dp(unit.Dp(3))
				pillH := gtx.Dp(unit.Dp(16))
				centerY := (gtx.Constraints.Min.Y - pillH) / 2
				if centerY < 0 {
					centerY = 0
				}
				rr := clip.UniformRRect(image.Rectangle{
					Min: image.Pt(0, centerY),
					Max: image.Pt(pillW, centerY+pillH),
				}, 2)
				paint.FillShape(gtx.Ops, colAccent, rr.Op(gtx.Ops))
				return layout.Dimensions{}
			}),
			// Content: Icon + Label
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(14), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body1(th, icon)
							iconCol := colTextTertiary
							if selected {
								iconCol = colAccent
							}
							lbl.Color = iconCol
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, label)
							lbl.Color = fg
							lbl.Font.Typeface = fontSegoe
							if selected {
								lbl.Font.Weight = font.SemiBold
							}
							return lbl.Layout(gtx)
						}),
					)
				})
			}),
		)
	})
}

func renderNavFooterBtn(gtx layout.Context, th *material.Theme, btn *widget.Clickable, icon, label string) layout.Dimensions {
	bg := color.NRGBA{}
	if btn.Hovered() {
		bg = colNavPaneHover
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				if bg.A > 0 {
					rr := clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, 6)
					paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
				}
				return layout.Dimensions{Size: gtx.Constraints.Min}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(14), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, icon)
							lbl.Color = colTextTertiary
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(th, label)
							lbl.Color = colTextSecondary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				})
			}),
		)
	})
}

// ============================================================================
// COMMON CONTROLS & HELPERS (WinUI 3 Fluent Cards, Buttons, Inputs)
// ============================================================================

// fluentCard renders a WinUI 3 rounded card with background fill and 1px border stroke.
func fluentCard(gtx layout.Context, bg, stroke color.NRGBA, radius int, content layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			rr := clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, radius)
			// Background fill
			paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
			// 1px Border stroke
			if stroke.A > 0 {
				border := clip.Stroke{
					Path:  rr.Path(gtx.Ops),
					Width: 1,
				}.Op()
				paint.FillShape(gtx.Ops, stroke, border)
			}
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(content),
	)
}

func renderAccentButton(gtx layout.Context, th *material.Theme, btn *widget.Clickable, text string) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bg := colAccent
		fg := colOnAccent
		if btn.Hovered() {
			bg = colAccentLight
		}
		if btn.Pressed() {
			bg = colAccentDark
		}
		return fluentCard(gtx, bg, color.NRGBA{}, 6, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(18), Right: unit.Dp(18)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, text)
				lbl.Color = fg
				lbl.Font.Weight = font.SemiBold
				lbl.Font.Typeface = fontSegoe
				return lbl.Layout(gtx)
			})
		})
	})
}

func renderStandardButton(gtx layout.Context, th *material.Theme, btn *widget.Clickable, text string) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bg := colControlBg
		stroke := colControlStroke
		fg := colTextPrimary
		if btn.Hovered() {
			bg = colControlBgHover
		}
		if btn.Pressed() {
			bg = colControlBgPressed
		}
		return fluentCard(gtx, bg, stroke, 6, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, text)
				lbl.Color = fg
				lbl.Font.Weight = font.Medium
				lbl.Font.Typeface = fontSegoe
				return lbl.Layout(gtx)
			})
		})
	})
}

func renderDangerButton(gtx layout.Context, th *material.Theme, btn *widget.Clickable, text string) layout.Dimensions {
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bg := colErrorContainer
		stroke := colErrorStroke
		fg := colTextPrimary
		if btn.Hovered() {
			bg = color.NRGBA{R: 0x66, G: 0x2A, B: 0x32, A: 0xFF}
			stroke = color.NRGBA{R: 0x93, G: 0x35, B: 0x41, A: 0xFF}
		}
		if btn.Pressed() {
			bg = color.NRGBA{R: 0x44, G: 0x1B, B: 0x20, A: 0xFF}
		}
		return fluentCard(gtx, bg, stroke, 6, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, text)
				lbl.Color = fg
				lbl.Font.Weight = font.SemiBold
				lbl.Font.Typeface = fontSegoe
				return lbl.Layout(gtx)
			})
		})
	})
}

func renderPageHeader(gtx layout.Context, th *material.Theme, title, subtitle string, rightWidget layout.Widget) layout.Dimensions {
	return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.H5(th, title)
						lbl.Color = colTextPrimary
						lbl.Font.Weight = font.Bold
						lbl.Font.Typeface = fontSegoe
						return lbl.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Body2(th, subtitle)
						lbl.Color = colTextSecondary
						lbl.Font.Typeface = fontSegoe
						return lbl.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if rightWidget != nil {
					return rightWidget(gtx)
				}
				return layout.Dimensions{}
			}),
		)
	})
}

// renderSettingsCard renders a WinUI 3 SettingsCard: title + subtitle on the left, control on the right.
func renderSettingsCard(gtx layout.Context, th *material.Theme, title, subtitle string, control layout.Widget) layout.Dimensions {
	return fluentCard(gtx, colCardBg, colCardStroke, 8, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, title)
							lbl.Color = colTextPrimary
							lbl.Font.Weight = font.SemiBold
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(th, subtitle)
							lbl.Color = colTextSecondary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				layout.Rigid(control),
			)
		})
	})
}

// ============================================================================
// TAB 1: СОСТОЯНИЕ (Status & Telemetry)
// ============================================================================

func renderStatusPage(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	s := st.st
	busy := st.busy
	st.mu.Unlock()

	return layout.Inset{Top: unit.Dp(20), Bottom: unit.Dp(20), Left: unit.Dp(24), Right: unit.Dp(24)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		widgets := []layout.Widget{
			// Page Header with Status Badge
			func(gtx layout.Context) layout.Dimensions {
				return renderPageHeader(gtx, th, "Состояние", "Мониторинг соединений, телеметрия и управление службой", func(gtx layout.Context) layout.Dimensions {
					return renderStatusBadge(gtx, th, s.Running, s.Redirector)
				})
			},
			// UAC Elevation Warning InfoBar (WinUI 3 InfoBar)
			func(gtx layout.Context) layout.Dimensions {
				return renderElevationInfoBar(st, gtx, th)
			},
			// Hero Card
			func(gtx layout.Context) layout.Dimensions {
				return renderHeroCard(st, gtx, th, s, busy)
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// DC Matrix Card
			func(gtx layout.Context) layout.Dimensions {
				return renderDCMatrixCard(gtx, th, s)
			},
			func(gtx layout.Context) layout.Dimensions {
				return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
			},
			// Service Endpoints Card
			func(gtx layout.Context) layout.Dimensions {
				return renderServiceInfoCard(st, gtx, th, s)
			},
		}

		return st.contentList.Layout(gtx, len(widgets), func(gtx layout.Context, i int) layout.Dimensions {
			return widgets[i](gtx)
		})
	})
}

func renderStatusBadge(gtx layout.Context, th *material.Theme, running, redirector bool) layout.Dimensions {
	bg := colErrorContainer
	stroke := colErrorStroke
	fg := colError
	text := "● Остановлен"
	if running && redirector {
		bg = colSuccessContainer
		stroke = colSuccessStroke
		fg = colSuccess
		text = "● Активен (WinDivert)"
	} else if running {
		bg = colAccentContainer
		stroke = color.NRGBA{R: 0x00, G: 0x5C, B: 0x94, A: 0xFF}
		fg = colAccent
		text = "● Активен (SOCKS5 / WSS)"
	}

	return fluentCard(gtx, bg, stroke, 12, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(th, text)
			lbl.Color = fg
			lbl.Font.Weight = font.SemiBold
			lbl.Font.Typeface = fontSegoe
			return lbl.Layout(gtx)
		})
	})
}

func renderElevationInfoBar(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	if runtime.GOOS != "windows" || isElevated() {
		return layout.Dimensions{}
	}

	return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return fluentCard(gtx, colWarningContainer, colWarningStroke, 8, func(gtx layout.Context) layout.Dimensions {
			return layout.Stack{}.Layout(gtx,
				// Left warning accent line
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					barW := gtx.Dp(unit.Dp(4))
					rr := clip.RRect{
						Rect: image.Rectangle{Max: image.Pt(barW, gtx.Constraints.Min.Y)},
						NW:   gtx.Dp(unit.Dp(8)),
						SW:   gtx.Dp(unit.Dp(8)),
					}
					paint.FillShape(gtx.Ops, colWarning, rr.Op(gtx.Ops))
					return layout.Dimensions{}
				}),
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.H6(th, "⚠")
								lbl.Color = colWarning
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body2(th, "Требуются права Администратора")
										lbl.Color = colTextPrimary
										lbl.Font.Weight = font.Bold
										lbl.Font.Typeface = fontSegoe
										return lbl.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Caption(th, "Для сетевого перехвата WinDivert требуются права Администратора. Без них доступен только локальный SOCKS5.")
										lbl.Color = colTextSecondary
										lbl.Font.Typeface = fontSegoe
										return lbl.Layout(gtx)
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return renderAccentButton(gtx, th, &st.heroElevateBtn, "Перезапустить с UAC")
							}),
						)
					})
				}),
			)
		})
	})
}

func renderHeroCard(st *guiState, gtx layout.Context, th *material.Theme, s Status, busy bool) layout.Dimensions {
	return fluentCard(gtx, colCardBg, colCardStroke, 12, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				// Header row
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									stateText := "Служба активна"
									stateColor := colAccent
									if !s.Running {
										stateText = "Служба остановлена"
										stateColor = colTextTertiary
									}
									lbl := material.H6(th, stateText)
									lbl.Color = stateColor
									lbl.Font.Weight = font.Bold
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									sub := "DC1–DC5 через WebSocket · Прозрачный перехват (WinDivert)"
									if !s.Running {
										sub = "Нажмите «Запустить службу» для старта перехвата и туннелирования"
									}
									lbl := material.Body2(th, sub)
									lbl.Color = colTextSecondary
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
							)
						}),
						// Primary Start / Stop Button
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if s.Running {
								text := "Остановить"
								if busy {
									text = "Секунду…"
								}
								return renderDangerButton(gtx, th, &st.heroToggleBtn, text)
							}
							text := "Запустить службу"
							if busy {
								text = "Секунду…"
							}
							return renderAccentButton(gtx, th, &st.heroToggleBtn, text)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
						// Restart / Reapply Button
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderStandardButton(gtx, th, &st.heroRestartBtn, "Перезапустить")
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
				// 6 Metrics in seamless row
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					pop := s.LastCFPoP
					if pop == "" {
						pop = "—"
					}
					upStr := "↑" + formatBytes(s.TrafficUpBytes)
					downStr := "↓" + formatBytes(s.TrafficDownBytes)

					type metricItem struct {
						label string
						val1  string
						val2  string
					}

					metrics := []metricItem{
						{label: "Сессии", val1: strconv.FormatInt(s.Active, 10)},
						{label: "WS-сессии", val1: strconv.FormatInt(s.WS, 10)},
						{label: "Память RSS", val1: formatBytes(s.MemNowBytes)},
						{label: "Время работы", val1: formatUptime(s.Uptime)},
						{label: "Трафик", val1: upStr, val2: downStr},
						{label: "CF PoP", val1: pop},
					}

					children := make([]layout.FlexChild, 0, len(metrics))
					for _, m := range metrics {
						item := m
						children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									lbl := material.Caption(th, item.label)
									lbl.Color = colTextTertiary
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									if item.val2 != "" {
										return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Body1(th, item.val1)
												lbl.Color = colTextPrimary
												lbl.Font.Weight = font.Bold
												lbl.Font.Typeface = fontSegoe
												return lbl.Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												lbl := material.Body1(th, item.val2)
												lbl.Color = colTextPrimary
												lbl.Font.Weight = font.Bold
												lbl.Font.Typeface = fontSegoe
												return lbl.Layout(gtx)
											}),
										)
									}
									lbl := material.H6(th, item.val1)
									lbl.Color = colTextPrimary
									lbl.Font.Weight = font.Bold
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
							)
						}))
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
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

	return fluentCard(gtx, colCardBg, colCardStroke, 12, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body1(th, "Датацентры Telegram (DC Matrix)")
					lbl.Color = colTextPrimary
					lbl.Font.Weight = font.SemiBold
					lbl.Font.Typeface = fontSegoe
					return lbl.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					dcKeys := []string{"1", "2", "3", "4", "5"}
					children := make([]layout.FlexChild, 0, 5)

					for _, dc := range dcKeys {
						dcNum := dc
						count := s.DC[dcNum]
						city := cities[dcNum]

						children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									lbl := material.H6(th, "DC"+dcNum)
									lbl.Color = colAccent
									lbl.Font.Weight = font.Bold
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									lbl := material.Caption(th, city)
									lbl.Color = colTextTertiary
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									valCol := colTextTertiary
									if count > 0 {
										valCol = colSuccess
									}
									lbl := material.H4(th, strconv.Itoa(count))
									lbl.Color = valCol
									lbl.Font.Weight = font.Bold
									lbl.Font.Typeface = fontSegoe
									return lbl.Layout(gtx)
								}),
							)
						}))
					}
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
				// Summary bar
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderMetaChip(gtx, th, "Пул WSS", strconv.Itoa(s.PoolSize))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(20)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderMetaChip(gtx, th, "Попадания в пул", strconv.FormatInt(s.PoolHits, 10))
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(20)}.Layout),
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
			lbl.Color = colTextTertiary
			lbl.Font.Typeface = fontSegoe
			return lbl.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(th, val)
			lbl.Color = colTextPrimary
			lbl.Font.Weight = font.Bold
			lbl.Font.Typeface = fontSegoe
			return lbl.Layout(gtx)
		}),
	)
}

func renderServiceInfoCard(st *guiState, gtx layout.Context, th *material.Theme, s Status) layout.Dimensions {
	return fluentCard(gtx, colCardBg, colCardStroke, 12, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body1(th, "Интерфейсы и Службы")
							lbl.Color = colTextPrimary
							lbl.Font.Weight = font.SemiBold
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							socksPort := strconv.Itoa(s.Port)
							if socksPort == "0" {
								socksPort = "1080"
							}
							info := fmt.Sprintf("Локальный SOCKS5-прокси: 127.0.0.1:%s (для приложений без сетевого перехвата)", socksPort)
							lbl := material.Body2(th, info)
							lbl.Color = colTextSecondary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				}),
			)
		})
	})
}

// ============================================================================
// TAB 2: МАРШРУТИЗАЦИЯ (Routing / Settings)
// ============================================================================

func renderRoutingPage(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	busy := st.busy
	saveMsg := st.saveMsg
	saveMsgTime := st.saveMsgTime
	currentPool := st.poolSize
	st.mu.Unlock()

	return layout.Inset{Top: unit.Dp(20), Bottom: unit.Dp(20), Left: unit.Dp(24), Right: unit.Dp(24)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		items := []layout.Widget{
			// Page Header
			func(gtx layout.Context) layout.Dimensions {
				return renderPageHeader(gtx, th, "Маршрутизация", "Конфигурация Cloudflare WSS, DNS и параметров сети", nil)
			},
			// Section 1 Header
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body1(th, "Режим WebSocket & Cloudflare")
					lbl.Color = colAccent
					lbl.Font.Weight = font.Bold
					lbl.Font.Typeface = fontSegoe
					return lbl.Layout(gtx)
				})
			},
			// Toggles as SettingsCards
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swCFPriority, "Форсировать Cloudflare (CF Priority)", "Приоритетная маршрутизация всех Telegram DC через WSS")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swCFBalance, "Балансировка доменов (CF Balance)", "Распределение подключений по пулу доступных доменов Cloudflare")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swDoH, "Защищенный DNS (Multi-DoH гонка)", "Параллельная резолвация доменов через Cloudflare, Google и Quad9")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swH2Media, "HTTP/2 ускорение медиа (CF H2)", "Мультиплексирование загрузки фото и видео через HTTP/2 соединения")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swForceTestDC, "Тестовые датацентры (Test DC)", "Перехват и перенаправление тестовых серверов Telegram (149.154.175.10)")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderSettingsSwitchCard(gtx, th, &st.swDC203, "Прямой TCP-путь для CDN203", "Прямой маршрут без WSS для CDN-кэша медиафайлов")
			},
			// Section 2 Header
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body1(th, "Тонкая настройка адресов и пула")
					lbl.Color = colAccent
					lbl.Font.Weight = font.Bold
					lbl.Font.Typeface = fontSegoe
					return lbl.Layout(gtx)
				})
			},
			// Inputs as SettingsCards
			func(gtx layout.Context) layout.Dimensions {
				return renderTextInputCard(gtx, th, &st.edCustomDomain, "например: my-worker.example.com", "Свой Cloudflare-домен (Фронтинг)", "Кастомный SNI / HTTP Host для обхода локальных блокировок")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderTextInputCard(gtx, th, &st.edCustomWorker, "например: my-worker.username.workers.dev", "Шлюз Cloudflare Worker", "Персональный воркер (cloudflare:sockets) для WSS релея")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderTextInputCard(gtx, th, &st.edDCOverrides, "1:149.154.175.50, 2:149.154.167.220", "Ручные IP для DC (опционально)", "Прямое переопределение IP-адресов датацентров")
			},
			func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) },
			func(gtx layout.Context) layout.Dimensions {
				return renderPoolSegmentedCard(st, gtx, th, currentPool)
			},
			// Save Action Button
			func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btnText := "Сохранить настройки"
							if busy {
								btnText = "Сохранение…"
							}
							return renderAccentButton(gtx, th, &st.saveConfigBtn, btnText)
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
								lbl.Font.Typeface = fontSegoe
								return lbl.Layout(gtx)
							}
							return layout.Dimensions{}
						}),
					)
				})
			},
		}

		return st.contentList.Layout(gtx, len(items), func(gtx layout.Context, i int) layout.Dimensions {
			return items[i](gtx)
		})
	})
}

func renderSettingsSwitchCard(gtx layout.Context, th *material.Theme, sw *widget.Bool, title, subtitle string) layout.Dimensions {
	return renderSettingsCard(gtx, th, title, subtitle, func(gtx layout.Context) layout.Dimensions {
		s := material.Switch(th, sw, "")
		s.Color.Enabled = colAccent
		s.Color.Disabled = colCardStroke
		s.Color.Track = colAccentContainer
		return s.Layout(gtx)
	})
}

func renderTextInputCard(gtx layout.Context, th *material.Theme, ed *widget.Editor, hint, title, subtitle string) layout.Dimensions {
	return fluentCard(gtx, colCardBg, colCardStroke, 8, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, title)
							lbl.Color = colTextPrimary
							lbl.Font.Weight = font.SemiBold
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(th, subtitle)
							lbl.Color = colTextSecondary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(unit.Dp(260))
					gtx.Constraints.Max.X = gtx.Dp(unit.Dp(260))
					return fluentCard(gtx, colControlBg, colControlStroke, 4, func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							editor := material.Editor(th, ed, hint)
							editor.Color = colTextPrimary
							editor.HintColor = colTextTertiary
							editor.Font.Typeface = fontSegoe
							return editor.Layout(gtx)
						})
					})
				}),
			)
		})
	})
}

func renderPoolSegmentedCard(st *guiState, gtx layout.Context, th *material.Theme, currentPool int) layout.Dimensions {
	return fluentCard(gtx, colCardBg, colCardStroke, 8, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(th, "Пул предпрогретых WSS-сокетов")
							lbl.Color = colTextPrimary
							lbl.Font.Weight = font.SemiBold
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(th, "Фоновое поддержание открытых WebSocket для мгновенного отклика Telegram")
							lbl.Color = colTextSecondary
							lbl.Font.Typeface = fontSegoe
							return lbl.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderPoolOption(gtx, th, &st.poolBtn0, "0", currentPool == 0)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderPoolOption(gtx, th, &st.poolBtn1, "1", currentPool == 1)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderPoolOption(gtx, th, &st.poolBtn2, "2", currentPool == 2)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return renderPoolOption(gtx, th, &st.poolBtn4, "4", currentPool == 4)
						}),
					)
				}),
			)
		})
	})
}

func renderPoolOption(gtx layout.Context, th *material.Theme, btn *widget.Clickable, label string, selected bool) layout.Dimensions {
	bg := colControlBg
	stroke := colControlStroke
	fg := colTextSecondary
	if selected {
		bg = colAccent
		stroke = colAccent
		fg = colOnAccent
	} else if btn.Hovered() {
		bg = colControlBgHover
	}
	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return fluentCard(gtx, bg, stroke, 4, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(th, label)
				lbl.Color = fg
				lbl.Font.Typeface = fontSegoe
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

func renderLogsPage(st *guiState, gtx layout.Context, th *material.Theme) layout.Dimensions {
	st.mu.Lock()
	logText := st.st.Log
	st.mu.Unlock()

	lines := strings.Split(strings.TrimRight(logText, "\r\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{"Журнал пуст (служба не записывала событий)"}
	}

	return layout.Inset{Top: unit.Dp(20), Bottom: unit.Dp(20), Left: unit.Dp(24), Right: unit.Dp(24)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Header
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return renderPageHeader(gtx, th, "Журнал событий", fmt.Sprintf("События службы и WinDivert в реальном времени (%d строк)", len(lines)), func(gtx layout.Context) layout.Dimensions {
					return renderDangerButton(gtx, th, &st.clearLogsBtn, "Очистить журнал")
				})
			}),
			// Terminal View
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return fluentCard(gtx, colTerminalBg, colDivider, 8, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return st.logsList.Layout(gtx, len(lines), func(gtx layout.Context, i int) layout.Dimensions {
							line := lines[i]
							lineColor := colTextSecondary

							lower := strings.ToLower(line)
							if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "fatal") {
								lineColor = colError
							} else if strings.Contains(lower, "active") || strings.Contains(lower, "started") || strings.Contains(lower, "listening") {
								lineColor = colSuccess
							} else if strings.Contains(lower, "wss") || strings.Contains(lower, "dc") {
								lineColor = colAccent
							}

							return layout.Inset{Bottom: unit.Dp(2)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								lbl := material.Caption(th, line)
								lbl.Color = lineColor
								lbl.Font.Typeface = fontMono
								return lbl.Layout(gtx)
							})
						})
					})
				})
			}),
		)
	})
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
