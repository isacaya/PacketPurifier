import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PacketPurifier implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JProgressBar progressBar;
    private JComboBox<String> filterComboBox;
    private JTextArea requestEditor;
    private HttpRequest currentRequest;
    private HttpResponse originalResponse1;
    private HttpResponse originalResponse2;
    private AtomicInteger tasksRemaining;
    private ExecutorService executor;
    private Color backgroundColor;
    private Color foregroundColor;
    private Color buttonColor;
    private Map<Integer, RequestResponsePair> requestResponseMap;
    private JTextArea detailRequestArea;
    private JTextPane detailResponseArea;
    private JLabel notificationLabel;
    private List<Integer> dynamicLines = new ArrayList<>();

    private static class RequestResponsePair {
        HttpRequest request;
        HttpResponse response;

        RequestResponsePair(HttpRequest request, HttpResponse response) {
            this.request = request;
            this.response = response;
        }
    }

    private static class InfluentialElement {
        String type;
        String name;

        InfluentialElement(String type, String name) {
            this.type = type;
            this.name = name;
        }
    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.executor = Executors.newFixedThreadPool(5);
        this.tasksRemaining = new AtomicInteger(0);
        this.requestResponseMap = new HashMap<>();

        // Set theme colors based on Burp Suite's theme
        setThemeColors();

        api.extension().setName("PacketPurifier");
        api.userInterface().registerContextMenuItemsProvider(this);
        createUITab();

        api.logging().logToOutput("PacketPurifier initialized.");
    }

    private void setThemeColors() {
        Theme theme = api.userInterface().currentTheme();
        if (theme == Theme.DARK) {
            backgroundColor = new Color(40, 44, 52); // Dark theme background
            foregroundColor = Color.WHITE;
            buttonColor = new Color(63, 81, 181); // Blue for buttons (dark)
        } else {
            backgroundColor = Color.WHITE; // Light theme background
            foregroundColor = Color.BLACK;
            buttonColor = new Color(33, 150, 243); // Blue for buttons (light)
        }
    }

    private void createUITab() {
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        mainPanel.setBackground(backgroundColor);

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        toolbar.setBackground(backgroundColor);

        // Filter dropdown
        JLabel filterLabel = new JLabel("Analyze:");
        filterLabel.setForeground(foregroundColor);
        filterLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        String[] filterOptions = {"All", "Parameters", "Cookies", "Headers"};
        filterComboBox = new JComboBox<>(filterOptions);
        filterComboBox.setFont(new Font("Arial", Font.PLAIN, 12));
        filterComboBox.setBackground(backgroundColor);
        filterComboBox.setForeground(foregroundColor);

        // Buttons
        JButton analyzeButton = new JButton("Analyze Request");
        analyzeButton.setFont(new Font("Arial", Font.PLAIN, 12));
        analyzeButton.setBackground(buttonColor);
        analyzeButton.setForeground(Color.WHITE);
        analyzeButton.addActionListener(e -> analyzeRequestFromEditor());

        JButton clearButton = new JButton("Clear");
        clearButton.setFont(new Font("Arial", Font.PLAIN, 12));
        clearButton.setBackground(buttonColor);
        clearButton.setForeground(Color.WHITE);
        clearButton.addActionListener(e -> clearResults());

        // Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setForeground(new Color(76, 175, 80));
        progressBar.setBackground(backgroundColor.equals(Color.WHITE) ? Color.LIGHT_GRAY : new Color(60, 64, 72));
        progressBar.setPreferredSize(new Dimension(150, 20));

        // Notification label
        notificationLabel = new JLabel("");
        notificationLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        notificationLabel.setForeground(foregroundColor);
        notificationLabel.setBackground(backgroundColor);
        notificationLabel.setHorizontalAlignment(SwingConstants.RIGHT);

        // Add components to toolbar
        toolbar.add(analyzeButton);
        toolbar.add(clearButton);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(filterLabel);
        toolbar.add(filterComboBox);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(progressBar);
        toolbar.add(Box.createHorizontalGlue()); // Push notificationLabel to the right
        toolbar.add(notificationLabel);

        // Request editor
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBackground(backgroundColor);
        requestPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY), "Request", 0, 0, new Font("Arial", Font.BOLD, 12), foregroundColor));

        requestEditor = new JTextArea(10, 20);
        requestEditor.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestEditor.setBackground(backgroundColor.equals(Color.WHITE) ? new Color(245, 245, 245) : new Color(50, 54, 62));
        requestEditor.setForeground(foregroundColor);
        requestEditor.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        requestEditor.setEditable(false); // Make read-only

        // Add line numbers
        JTextArea lineNumbers = new JTextArea("1");
        lineNumbers.setBackground(backgroundColor.equals(Color.WHITE) ? new Color(230, 230, 230) : new Color(45, 49, 57));
        lineNumbers.setForeground(foregroundColor);
        lineNumbers.setFont(new Font("Monospaced", Font.PLAIN, 12));
        lineNumbers.setEditable(false);
        lineNumbers.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        requestEditor.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers(); }
            private void updateLineNumbers() {
                int lineCount = requestEditor.getLineCount();
                StringBuilder numbers = new StringBuilder();
                for (int i = 1; i <= lineCount; i++) {
                    numbers.append(i).append("\n");
                }
                lineNumbers.setText(numbers.toString());
            }
        });

        JScrollPane requestScroll = new JScrollPane(requestEditor);
        requestScroll.setRowHeaderView(lineNumbers);
        requestPanel.add(requestScroll, BorderLayout.CENTER);

        // Results panel
        JPanel resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.setBackground(backgroundColor);
        resultsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY), "Results", 0, 0, new Font("Arial", Font.BOLD, 12), foregroundColor));

        String[] columns = {"URL", "Element Type", "Element Name"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable resultTable = new JTable(tableModel);
        resultTable.setFillsViewportHeight(true);
        resultTable.setFont(new Font("Arial", Font.PLAIN, 12));
        resultTable.getTableHeader().setFont(new Font("Arial", Font.BOLD, 12));
        resultTable.setBackground(backgroundColor.equals(Color.WHITE) ? Color.WHITE : new Color(50, 54, 62));
        resultTable.setForeground(foregroundColor);
        resultTable.setGridColor(Color.GRAY);
        resultTable.setRowHeight(25);

        // Add mouse listener for row clicks
        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = resultTable.getSelectedRow();
                if (row >= 0) {
                    RequestResponsePair pair = requestResponseMap.get(row);
                    if (pair != null) {
                        detailRequestArea.setText(pair.request.toString());
                        displayResponseWithHighlights(pair.response);
                        detailRequestArea.setCaretPosition(0);
                    } else {
                        detailRequestArea.setText("");
                        detailResponseArea.setText("");
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(resultTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        resultsPanel.add(tableScroll, BorderLayout.CENTER);

        // Details panel for request/response
        JPanel detailsPanel = new JPanel(new BorderLayout());
        detailsPanel.setBackground(backgroundColor);
        detailsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY), "Details", 0, 0, new Font("Arial", Font.BOLD, 12), foregroundColor));

        detailRequestArea = new JTextArea(5, 20);
        detailRequestArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        detailRequestArea.setBackground(backgroundColor.equals(Color.WHITE) ? new Color(245, 245, 245) : new Color(50, 54, 62));
        detailRequestArea.setForeground(foregroundColor);
        detailRequestArea.setEditable(false);
        JScrollPane detailRequestScroll = new JScrollPane(detailRequestArea);
        detailRequestScroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY), "Sent Request", 0, 0, new Font("Arial", Font.PLAIN, 12), foregroundColor));

        detailResponseArea = new JTextPane();
        detailResponseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        detailResponseArea.setBackground(backgroundColor.equals(Color.WHITE) ? new Color(245, 245, 245) : new Color(50, 54, 62));
        detailResponseArea.setForeground(foregroundColor);
        detailResponseArea.setEditable(false);
        JScrollPane detailResponseScroll = new JScrollPane(detailResponseArea);
        detailResponseScroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY), "Received Response", 0, 0, new Font("Arial", Font.PLAIN, 12), foregroundColor));

        JSplitPane detailsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, detailRequestScroll, detailResponseScroll);
        detailsSplit.setDividerLocation(300);
        detailsSplit.setBackground(backgroundColor);
        detailsPanel.add(detailsSplit, BorderLayout.CENTER);

        // Combine results and details in a vertical split
        JSplitPane resultsAndDetailsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsPanel, detailsPanel);
        resultsAndDetailsSplit.setDividerLocation(200);
        resultsAndDetailsSplit.setBackground(backgroundColor);

        // Main vertical split
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestPanel, resultsAndDetailsSplit);
        mainSplit.setDividerLocation(200);
        mainSplit.setBackground(backgroundColor);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("PacketPurifier", mainPanel);
    }

    private void analyzeRequestFromEditor() {
        if (requestEditor.getText().isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                notificationLabel.setText("No request loaded. Please select a request.");
                new Timer(2000, (ActionListener) e -> notificationLabel.setText("")).start();
            });
            return;
        }
        try {
            String editedRequest = requestEditor.getText();
            HttpService service = null;
            if (currentRequest != null) {
                service = currentRequest.httpService();
            } else {
                // Attempt to infer HttpService from Host header
                String host = extractHostFromRequest(editedRequest);
                if (host != null) {
                    service = HttpService.httpService(host, 443, true); // Assume HTTPS
                } else {
                    throw new IllegalArgumentException("No Host header found in request.");
                }
            }
            HttpRequest modifiedRequest = HttpRequest.httpRequest(service, editedRequest);
            analyzeRequest(modifiedRequest);
        } catch (Exception e) {
            api.logging().logToError("Error parsing edited request: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                notificationLabel.setText("Invalid request format.");
                new Timer(2000, (ActionListener) e1 -> notificationLabel.setText("")).start();
            });
        }
    }

    private String extractHostFromRequest(String rawRequest) {
        Pattern hostPattern = Pattern.compile("Host: ([^\r\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = hostPattern.matcher(rawRequest);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        progressBar.setValue(0);
        progressBar.setString("Ready");
        detailRequestArea.setText("");
        detailResponseArea.setText("");
        originalResponse1 = null;
        originalResponse2 = null;
        dynamicLines.clear();
        requestResponseMap.clear();
        notificationLabel.setText("");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            JMenuItem analyzeItem = new JMenuItem("Send to PacketPurifier");
            analyzeItem.setFont(new Font("Arial", Font.PLAIN, 12));
            analyzeItem.addActionListener(e -> loadRequest(event.messageEditorRequestResponse().get().requestResponse().request()));
            menuItems.add(analyzeItem);
        }
        return menuItems;
    }

    private void loadRequest(HttpRequest request) {
        currentRequest = request;
        SwingUtilities.invokeLater(() -> {
            requestEditor.setText(request.toString());
            requestEditor.setCaretPosition(0);
            tableModel.setRowCount(0);
            progressBar.setValue(0);
            progressBar.setString("Ready");
            detailRequestArea.setText("");
            detailResponseArea.setText("");
            originalResponse1 = null;
            originalResponse2 = null;
            dynamicLines.clear();
            requestResponseMap.clear();
            notificationLabel.setText("");
        });
    }

    private void analyzeRequest(HttpRequest originalRequest) {
        executor.submit(() -> {
            try {
                List<InfluentialElement> influentialElements = new ArrayList<>();
                int totalTasks = 0;
                String filter = (String) filterComboBox.getSelectedItem();
                if (filter.equals("All") || filter.equals("Parameters")) {
                    totalTasks += originalRequest.parameters().stream()
                        .filter(p -> p.type() != HttpParameterType.COOKIE)
                        .count();
                }
                if (filter.equals("All") || filter.equals("Cookies")) {
                    totalTasks += originalRequest.parameters(HttpParameterType.COOKIE).size();
                }
                if (filter.equals("All") || filter.equals("Headers")) {
                    totalTasks += originalRequest.headers().stream()
                        .filter(h -> !h.name().equalsIgnoreCase("Host"))
                        .count();
                }
                tasksRemaining.set(totalTasks);
                updateProgress(0, totalTasks);

                // Send baseline request twice to detect dynamic parts
                originalResponse1 = api.http().sendRequest(originalRequest).response();
                Thread.sleep(1500); // 1.5 second interval (for removing values that change on a per-second basis)
                originalResponse2 = api.http().sendRequest(originalRequest).response();

                // Identify dynamic lines
                dynamicLines.clear();
                String[] lines1 = originalResponse1.toString().split("\n");
                String[] lines2 = originalResponse2.toString().split("\n");
                for (int i = 0; i < Math.min(lines1.length, lines2.length); i++) {
                    if (!lines1[i].equals(lines2[i])) {
                        dynamicLines.add(i);
                    }
                }

                if (filter.equals("All") || filter.equals("Parameters")) {
                    for (HttpParameter param : originalRequest.parameters()) {
                        if (param.type() != HttpParameterType.COOKIE) {
                            HttpRequest modifiedRequest = originalRequest.withRemovedParameters(param);
                            boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, originalResponse1, "Parameter", param.name(), totalTasks);
                            if (hasImpact) {
                                influentialElements.add(new InfluentialElement("Parameter", param.name()));
                            }
                        }
                    }
                }

                if (filter.equals("All") || filter.equals("Cookies")) {
                    for (HttpParameter cookie : originalRequest.parameters(HttpParameterType.COOKIE)) {
                        HttpRequest modifiedRequest = originalRequest.withRemovedParameters(cookie);
                        boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, originalResponse1, "Cookie", cookie.name(), totalTasks);
                        if (hasImpact) {
                            influentialElements.add(new InfluentialElement("Cookie", cookie.name()));
                        }
                    }
                }

                if (filter.equals("All") || filter.equals("Headers")) {
                    for (HttpHeader header : originalRequest.headers()) {
                        if (!header.name().equalsIgnoreCase("Host")) {
                            HttpRequest modifiedRequest = originalRequest.withRemovedHeader(header.name());
                            boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, originalResponse1, "Header", header.name(), totalTasks);
                            if (hasImpact) {
                                influentialElements.add(new InfluentialElement("Header", header.name()));
                            }
                        }
                    }
                }

                // Create and send minimized packet to Repeater
                HttpRequest minimizedRequest = createMinimizedRequest(originalRequest, influentialElements);
                api.repeater().sendToRepeater(minimizedRequest);

                // Notify user
                final int finalTotalTasks = totalTasks; // Make effectively final
                SwingUtilities.invokeLater(() -> {
                    updateProgress(finalTotalTasks, finalTotalTasks);
                    notificationLabel.setText("Analysis complete. Minimized packet sent to Repeater.");
                    new Timer(2000, (ActionListener) e -> notificationLabel.setText("")).start();
                });
            } catch (Exception e) {
                api.logging().logToError("Error analyzing request: " + e.getMessage());
                if (e instanceof InterruptedException) {
                    api.logging().logToError("Interrupted during baseline sleep: " + e.getMessage());
                }
                final int finalTotalTasks = tasksRemaining.get(); // Make effectively final for error case
                SwingUtilities.invokeLater(() -> {
                    tableModel.addRow(new Object[]{
                        originalRequest.url(), "Error", "N/A"
                    });
                    updateProgress(finalTotalTasks, finalTotalTasks);
                    notificationLabel.setText("Error during analysis.");
                    new Timer(2000, (ActionListener) e1 -> notificationLabel.setText("")).start();
                });
            }
        });
    }

    private boolean testElementRemoval(HttpRequest originalRequest, HttpRequest modifiedRequest, HttpResponse originalResponse, String elementType, String elementName, int totalTasks) {
        try {
            HttpResponse modifiedResponse = api.http().sendRequest(modifiedRequest).response();
            boolean hasImpact = hasSignificantImpact(originalResponse, modifiedResponse);

            if (hasImpact) {
                int rowIndex = tableModel.getRowCount();
                SwingUtilities.invokeLater(() -> {
                    tableModel.addRow(new Object[]{
                        originalRequest.url(), elementType, elementName
                    });
                    requestResponseMap.put(rowIndex, new RequestResponsePair(modifiedRequest, modifiedResponse));
                });
            }
            return hasImpact;
        } catch (Exception e) {
            api.logging().logToError(String.format("Error testing %s '%s': %s", elementType, elementName, e.getMessage()));
            SwingUtilities.invokeLater(() -> {
                tableModel.addRow(new Object[]{
                    originalRequest.url(), elementType, elementName
                });
                requestResponseMap.put(tableModel.getRowCount() - 1, new RequestResponsePair(modifiedRequest, null));
            });
            return false;
        } finally {
            updateProgress(tasksRemaining.decrementAndGet(), totalTasks);
        }
    }

    private HttpRequest createMinimizedRequest(HttpRequest originalRequest, List<InfluentialElement> influentialElements) {
        HttpRequest minimizedRequest = originalRequest;

        // Collect all elements to keep
        List<String> keepParameters = new ArrayList<>();
        List<String> keepCookies = new ArrayList<>();
        List<String> keepHeaders = new ArrayList<>();

        for (InfluentialElement element : influentialElements) {
            if (element.type.equals("Parameter")) {
                keepParameters.add(element.name);
            } else if (element.type.equals("Cookie")) {
                keepCookies.add(element.name);
            } else if (element.type.equals("Header")) {
                keepHeaders.add(element.name);
            }
        }

        // Remove non-influential parameters
        for (HttpParameter param : originalRequest.parameters()) {
            if (param.type() != HttpParameterType.COOKIE && !keepParameters.contains(param.name())) {
                minimizedRequest = minimizedRequest.withRemovedParameters(param);
            }
        }

        // Remove non-influential cookies
        for (HttpParameter cookie : originalRequest.parameters(HttpParameterType.COOKIE)) {
            if (!keepCookies.contains(cookie.name())) {
                minimizedRequest = minimizedRequest.withRemovedParameters(cookie);
            }
        }

        // Remove non-influential headers (except Host)
        for (HttpHeader header : originalRequest.headers()) {
            if (!header.name().equalsIgnoreCase("Host") && !keepHeaders.contains(header.name())) {
                minimizedRequest = minimizedRequest.withRemovedHeader(header.name());
            }
        }

        return minimizedRequest;
    }

    private void displayResponseWithHighlights(HttpResponse modifiedResponse) {
        detailResponseArea.setText("");
        if (modifiedResponse == null || originalResponse1 == null) {
            detailResponseArea.setText(modifiedResponse == null ? "No response available" : modifiedResponse.toString());
            return;
        }

        String[] originalLines = originalResponse1.toString().split("\n");
        String[] modifiedLines = modifiedResponse.toString().split("\n");
        StyledDocument doc = detailResponseArea.getStyledDocument();
        Style defaultStyle = doc.addStyle("default", null);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 12);
        StyleConstants.setForeground(defaultStyle, foregroundColor);

        Style highlightStyle = doc.addStyle("highlight", defaultStyle);
        StyleConstants.setBackground(highlightStyle, buttonColor); // Use button color for highlight

        try {
            int maxLines = Math.max(originalLines.length, modifiedLines.length);
            for (int i = 0; i < maxLines; i++) {
                String originalLine = i < originalLines.length ? originalLines[i] : "";
                String modifiedLine = i < modifiedLines.length ? modifiedLines[i] : "";
                String lineToDisplay = modifiedLine + "\n";
                if (!originalLine.equals(modifiedLine) && !dynamicLines.contains(i)) {
                    doc.insertString(doc.getLength(), lineToDisplay, highlightStyle);
                } else {
                    doc.insertString(doc.getLength(), lineToDisplay, defaultStyle);
                }
            }
            detailResponseArea.setCaretPosition(0);
        } catch (BadLocationException e) {
            api.logging().logToError("Error displaying response: " + e.getMessage());
            detailResponseArea.setText("Error displaying response: " + e.getMessage());
        }
    }

    private void updateProgress(int remaining, int total) {
        SwingUtilities.invokeLater(() -> {
            int progress = total > 0 ? (int) ((double) (total - remaining) / total * 100) : 100;
            progressBar.setValue(progress);
            progressBar.setString(progress < 100 ? "Analyzing: " + progress + "%" : "Complete");
        });
    }

    private boolean hasSignificantImpact(HttpResponse original, HttpResponse modified) {
        boolean statusDiff = original.statusCode() != modified.statusCode();
        String normalizedOriginal = normalizeResponse(original.toString());
        String normalizedModified = normalizeResponse(modified.toString());
        boolean contentDiff = !normalizedOriginal.equals(normalizedModified);
        return statusDiff || contentDiff;
    }

    private String normalizeResponse(String responseStr) {
        String[] lines = responseStr.split("\n");
        for (int lineIndex : dynamicLines) {
            if (lineIndex < lines.length) {
                lines[lineIndex] = "__PP_DYNAMIC_LINE__";
            }
        }
        return String.join("\n", lines);
    }
}