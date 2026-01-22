let total = 0;

document.querySelectorAll('img[id]').forEach(img => {
    const id = img.id;
    if (!id.includes("-")) return;

    const parts = id.split("-");
    const company = parts[0];
    const gameSlug = parts.slice(1).join("-");

    const gameName = gameSlug
        .split("-")
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");

    const link = img.src;

    console.log(`${company} – ${gameName} – ${link}`);

    total++;
});

console.log(`\nTotal games found: ${total}`);
