/*
Some of the SpectreConsole code is internal, so copied here for reuse.

The following license applies to this code:

MIT License

Copyright (c) 2020 Patrik Svensson, Phil Scott, Nils Andresen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using Spectre.Console;

namespace AzureSecurityAnalyzer.OutputFormatters.SpectreConsole;

public class StatusContext
{
    private readonly ProgressContext context = default!;
    private readonly ProgressTask? task;
    private readonly SpinnerColumn spinnerColumn = default!;

    /// <summary>
    /// Gets or sets the current status.
    /// </summary>
    public string? Status
    {
        get => task?.Description;
        set => SetStatus(value);
    }

    /// <summary>
    /// Gets or sets the current spinner.
    /// </summary>
    public Spinner Spinner
    {
        get => spinnerColumn.Spinner;
        set => SetSpinner(value);
    }

    /// <summary>
    /// Gets or sets the current spinner style.
    /// </summary>
    public Style? SpinnerStyle
    {
        get => spinnerColumn.Style;
        set => spinnerColumn.Style = value;
    }

    internal StatusContext()
    {
        
    }
    
    internal StatusContext(ProgressContext context, ProgressTask task, SpinnerColumn spinnerColumn)
    {
        this.context = context ?? throw new ArgumentNullException(nameof(context));
        this.task = task ?? throw new ArgumentNullException(nameof(task));
        this.spinnerColumn = spinnerColumn ?? throw new ArgumentNullException(nameof(spinnerColumn));
    }

    /// <summary>
    /// Refreshes the status.
    /// </summary>
    public void Refresh()
    {
        context.Refresh();
    }

    private void SetStatus(string? status)
    {
        task!.Description = status ?? string.Empty;
    }

    private void SetSpinner(Spinner spinner)
    {
        ArgumentNullException.ThrowIfNull(spinner);

        spinnerColumn.Spinner = spinner;
    }
}