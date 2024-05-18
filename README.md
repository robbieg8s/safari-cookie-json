Parse a Safari Binary Cookies file and emit as JSON so you can extract cookies for scripting.

A C port of https://github.com/interstateone/BinaryCookies/ which emits JSON instead of text.

See also https://www.toolbox.com/tech/operating-systems/blogs/understanding-the-safari-cookiesbinarycookies-file-format-010712/ for
a description of the format.

Build it via

    make safari-cookie-json

Use it via

    ./safari-cookie-json "${HOME}"/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies
