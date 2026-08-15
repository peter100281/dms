(() => {
  const input =
    document.getElementById('tags-input');

  const box =
    document.getElementById('tag-suggestions');

  if (!input || !box) {
    return;
  }


  let timer = null;
  let selectedIndex = -1;
  let suggestions = [];


  function splitTags(value) {
    return value
      .split(',')
      .map(tag => tag.trim())
      .filter(Boolean);
  }


  function currentFragment() {
    const parts =
      input.value.split(',');

    return (
      parts[parts.length - 1] || ''
    ).trim();
  }


  function existingTags() {
    const parts =
      input.value.split(',');

    /*
      Das letzte Element ist gerade der
      Tag, den der Benutzer noch tippt.
    */
    parts.pop();

    return parts
      .map(tag => tag.trim().toLowerCase())
      .filter(Boolean);
  }


  function hideSuggestions() {
    box.hidden = true;
    box.innerHTML = '';
    selectedIndex = -1;
    suggestions = [];
  }


  function renderSuggestions(items) {
    const existing =
      new Set(existingTags());

    suggestions =
      items.filter(item =>
        !existing.has(
          item.name.toLowerCase()
        )
      );

    if (suggestions.length === 0) {
      hideSuggestions();
      return;
    }


    box.innerHTML = '';

    suggestions.forEach((item, index) => {
      const button =
        document.createElement('button');

      button.type = 'button';
      button.className =
        'tag-suggestion';

      const name =
        document.createElement('span');

      name.className =
        'tag-suggestion-name';

      name.textContent =
        item.name;


      const count =
        document.createElement('span');

      count.className =
        'tag-suggestion-count';

      count.textContent =
        item.usageCount === 1
          ? '1 Dokument'
          : `${item.usageCount} Dokumente`;


      button.appendChild(name);
      button.appendChild(count);


      button.addEventListener(
        'mousedown',
        event => {
          /*
            mousedown statt click verhindert,
            dass das Eingabefeld vorher den
            Fokus verliert.
          */
          event.preventDefault();

          chooseTag(
            item.name
          );
        }
      );


      button.dataset.index =
        String(index);

      box.appendChild(button);
    });


    box.hidden = false;
    selectedIndex = -1;
  }


  function updateSelection() {
    const buttons =
      box.querySelectorAll(
        '.tag-suggestion'
      );

    buttons.forEach(
      (button, index) => {
        button.classList.toggle(
          'selected',
          index === selectedIndex
        );
      }
    );


    if (
      selectedIndex >= 0 &&
      buttons[selectedIndex]
    ) {
      buttons[selectedIndex]
        .scrollIntoView({
          block: 'nearest'
        });
    }
  }


  function chooseTag(tagName) {
    const parts =
      input.value.split(',');

    /*
      Aktuellen unvollständigen Teil entfernen.
    */
    parts.pop();


    const completed =
      parts
        .map(tag => tag.trim())
        .filter(Boolean);


    const exists =
      completed.some(
        tag =>
          tag.toLowerCase() ===
          tagName.toLowerCase()
      );


    if (!exists) {
      completed.push(tagName);
    }


    input.value =
      completed.join(', ') + ', ';

    hideSuggestions();

    input.focus();
  }


  async function loadSuggestions() {
    const q =
      currentFragment();

    try {
      const response =
        await fetch(
          `/api/tags?q=${encodeURIComponent(q)}`,
          {
            headers: {
              Accept: 'application/json'
            }
          }
        );


      if (!response.ok) {
        hideSuggestions();
        return;
      }


      const items =
        await response.json();

      renderSuggestions(items);

    } catch (err) {
      console.error(
        'Tag-Suche fehlgeschlagen:',
        err
      );

      hideSuggestions();
    }
  }


  function scheduleLoad() {
    clearTimeout(timer);

    timer =
      setTimeout(
        loadSuggestions,
        120
      );
  }


  input.addEventListener(
    'focus',
    () => {
      scheduleLoad();
    }
  );


  input.addEventListener(
    'input',
    () => {
      scheduleLoad();
    }
  );


  input.addEventListener(
    'keydown',
    event => {

      if (box.hidden) {
        return;
      }


      if (event.key === 'ArrowDown') {
        event.preventDefault();

        selectedIndex =
          Math.min(
            selectedIndex + 1,
            suggestions.length - 1
          );

        updateSelection();
        return;
      }


      if (event.key === 'ArrowUp') {
        event.preventDefault();

        selectedIndex =
          Math.max(
            selectedIndex - 1,
            0
          );

        updateSelection();
        return;
      }


      if (
        event.key === 'Enter' &&
        selectedIndex >= 0
      ) {
        event.preventDefault();

        chooseTag(
          suggestions[selectedIndex].name
        );

        return;
      }


      if (event.key === 'Escape') {
        hideSuggestions();
      }
    }
  );


  document.addEventListener(
    'mousedown',
    event => {
      if (
        event.target !== input &&
        !box.contains(event.target)
      ) {
        hideSuggestions();
      }
    }
  );
})();
