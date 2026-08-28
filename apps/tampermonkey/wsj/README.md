# WSJ Clipper template

WSJ clip: `# title`, clip time, URL, body. No YAML. Note name: `Clip {{title}}`. Same import path as the FT template.

The Clipper settings page reuses one Import dialog for **templates** and **types.json**. If you opened Properties import first, the Import button still tries types.json and shows that error even when the template saved.

## Import

Use **`C:\Users\jar71\Downloads\wsj-clipper.json`**.

1. Left sidebar: click **Default** (a template, not Properties / General)
2. Drop the file on **Drag and drop file here** — do not use the bottom **Import** button if you already saw a types.json error
3. Click **OK** on any leftover alert
4. Look at the left list for **WSJ**. Keep it. Drag it above Default (and above FT if you clip both)

Console `Template import completed` means it worked. A later `Deleting template` means it was removed from the list.

Do not import from **Properties → Import** (that is `types.json` only).
