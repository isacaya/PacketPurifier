# PacketPurifier

![PacketPurifier](./PacketPurifier.png)

**PacketPurifier** is a Burp Suite extension designed to identify elements of packet (parameters, cookies, and headers) that influence server responses.

## Features

- **Highlighting the differences**: Highlight the lines where differences occur in the response.
- **Element Filtering**: It can choose which elements to include in the analysis.

## Installation

1. **Cloning the Repository**:
   - Clone or download the extension from the repository: `git clone https://github.com/isacaya/PacketPurifier.git`.

2. **Build the Extension**:
   - Run `./gradlew build` or `./gradlew jar`.

3. **Load in Burp Suite**:
   - Open Burp Suite
   - Go to `Extensions > Installed > Add`.
   - Select the `PacketPurifier/build/libs/PacketPurifier.jar` file and load it.
   - The "PacketPurifier" tab will appear in the Burp Suite interface.

## How to Use

Send the request packet to analyze to PacketPurifier via the context menu, then start Analyze Request. Check the results in the Results and Details panels below.