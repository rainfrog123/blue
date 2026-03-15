// Kill event listeners that block copying and right-clicking
const enableFunction = (e) => {
    e.stopPropagation();
    return true;
};

document.addEventListener('copy', enableFunction, true);
document.addEventListener('contextmenu', enableFunction, true);
document.addEventListener('selectstart', enableFunction, true);
document.addEventListener('mousedown', enableFunction, true);