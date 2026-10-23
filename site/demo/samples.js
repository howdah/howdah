// Demo samples. Every body is BENIGN filler built from a structural
// description (counts and shapes only). Nothing here is an exploit.
(function (root) {
  'use strict';
  var H = root.HowdahWasm || (typeof require !== 'undefined' ? require('./howdah-wasm.js') : null);

  function flood(n) {
    var parts = [];
    for (var i = 0; i < n; i++) parts.push({ name: 'f' + i });
    return H.buildBody(parts);
  }

  var samples = [
    {
      id: 'normal',
      title: 'Normal upload form',
      shape: 'Three text fields and one small file (a few bytes).',
      expect: { action: 'allow', rule: null },
      explain: 'An ordinary form post is within every limit, so Howdah lets it through.',
      build: function () {
        return H.buildBody([
          { name: 'title', content: 'Holiday photos' },
          { name: 'description', content: 'A few pictures from the trip.' },
          { name: 'tags', content: 'travel' },
          { name: 'photo', filename: 'beach.txt', content: 'placeholder file contents' }
        ]);
      }
    },
    {
      id: 'flood',
      title: 'Part flood (PHP2Shell-shaped)',
      shape: 'About 2,500 tiny empty parts, each well under a kilobyte.',
      expect: { action: 'block', rule: 'max_parts' },
      explain: 'A request made of thousands of tiny parts exhausts the server long before any file is stored; Howdah stops it at the part-count limit.',
      build: function () { return flood(2500); }
    },
    {
      id: 'malformed',
      title: 'Malformed multipart',
      shape: 'One well-formed field, then a part with no Content-Disposition header.',
      expect: { action: 'block', rule: 'malformed_multipart' },
      explain: 'A part that the multipart grammar does not allow is a sign of a confused or hostile parser input, so it is flagged as malformed.',
      build: function () {
        return H.buildBody([
          { name: 'a', content: 'ok' },
          { raw: '--' + H.BOUNDARY + '\r\nX-Note: no disposition here\r\n\r\nx\r\n' }
        ]);
      }
    },
    {
      id: 'filename',
      title: 'Oversized filename',
      shape: 'One file part whose filename is 600 characters long (default limit: 512 bytes).',
      expect: { action: 'block', rule: 'max_filename_len' },
      explain: 'Unreasonably long filenames are rejected at the filename-length limit.',
      build: function () {
        return H.buildBody([{ name: 'upload', filename: new Array(601).join('a') + '.txt', content: 'x' }]);
      }
    }
  ];

  root.HowdahSamples = samples;
  if (typeof module !== 'undefined' && module.exports) module.exports = samples;
})(typeof window !== 'undefined' ? window : globalThis);
