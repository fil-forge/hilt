package lib

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// NewTable returns a borderless, left-aligned table with upper-cased headers
// and space-aligned columns, for plain CLI listings.
func NewTable(w io.Writer) *tablewriter.Table {
	// Nothing before a cell and two spaces after it. The renderer repeats the
	// padding to fill the column, so this aligns columns with space and keeps
	// the line flush with the first cell.
	padding := tw.CellPadding{Global: tw.Padding{Left: tw.Empty, Right: "  ", Overwrite: true}}
	off := tw.Off
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.Border{Left: off, Right: off, Top: off, Bottom: off},
			Symbols: tw.NewSymbols(tw.StyleNone),
			Settings: tw.Settings{
				Separators: tw.Separators{ShowHeader: off, ShowFooter: off, BetweenRows: off, BetweenColumns: off},
				Lines:      tw.Lines{ShowTop: off, ShowBottom: off, ShowHeaderLine: off, ShowFooterLine: off},
			},
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Formatting: tw.CellFormatting{AutoWrap: tw.WrapNone, AutoFormat: tw.On},
				Alignment:  tw.CellAlignment{Global: tw.AlignLeft},
				Padding:    padding,
			},
			Row: tw.CellConfig{
				Formatting: tw.CellFormatting{AutoWrap: tw.WrapNone, AutoFormat: tw.Off},
				Alignment:  tw.CellAlignment{Global: tw.AlignLeft},
				Padding:    padding,
			},
			Behavior: tw.Behavior{TrimSpace: tw.On},
		}),
	)
}
