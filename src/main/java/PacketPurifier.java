import burp.api.montoya.BurpExtension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PacketPurifier implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JProgressBar progressBar;
    private JComboBox<String> filterComboBox;
    private JRadioButton basicMethod;
    private JRadioButton accurateMethod;
    private JSpinner baselineSpinner;
    private HttpRequestEditor requestEditor;
    private HttpRequest currentRequest;
    private List<HttpResponse> baselineResponses;
    private AtomicInteger tasksRemaining;
    private ExecutorService executor;
    private Map<Integer, HttpRequestResponse> requestResponseMap;
    private HttpRequestEditor detailRequestEditor;
    private HttpResponseEditor detailResponseEditor;
    private JLabel notificationLabel;
    private JButton analyzeButton;
    private JButton clearButton;
    private Map<Integer, PrefixPostfixPair> dynamicLinePrefixesPostfixes;
    private Set<Integer> dynamicLines;

    private static class PrefixPostfixPair {
        String prefix;
        String postfix;

        PrefixPostfixPair(String prefix, String postfix) {
            this.prefix = prefix;
            this.postfix = postfix;
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
        this.dynamicLinePrefixesPostfixes = new HashMap<>();
        this.dynamicLines = new HashSet<>();
        this.baselineResponses = new ArrayList<>();

        api.extension().setName("PacketPurifier");
        api.userInterface().registerContextMenuItemsProvider(this);
        createUITab();

        api.logging().logToOutput("PacketPurifier initialized.");
        api.extension().registerUnloadingHandler(this);
    }

    @Override
    public void extensionUnloaded() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
            api.logging().logToOutput("PacketPurifier executor shutdown complete.");
        }
    }



    private void createUITab() {
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

        // Filter dropdown
        JLabel filterLabel = new JLabel("Analyze:");
        String[] filterOptions = {"All", "Parameters", "Cookies", "Headers"};
        filterComboBox = new JComboBox<>(filterOptions);

        // Normalization radio buttons
        JLabel normalizationLabel = new JLabel("Normalization:");
        basicMethod = new JRadioButton("Basic", true);
        accurateMethod = new JRadioButton("Accurate", false);
        ButtonGroup normalizationGroup = new ButtonGroup();
        normalizationGroup.add(basicMethod);
        normalizationGroup.add(accurateMethod);

        // Baseline request spinner
        JLabel baselineLabel = new JLabel("Baseline Requests:");
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(3, 2, 10, 1); // Default 3, min 2, max 10
        baselineSpinner = new JSpinner(spinnerModel);
        baselineSpinner.setPreferredSize(new Dimension(50, 20));

        // Buttons
        analyzeButton = new JButton("Analyze Request");
        analyzeButton.addActionListener(e -> analyzeRequestFromEditor());

        clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearResults());

        // Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(250, 20));

        // Notification label
        notificationLabel = new JLabel("");
        notificationLabel.setHorizontalAlignment(SwingConstants.RIGHT);

        // Add components to toolbar
        toolbar.add(analyzeButton);
        toolbar.add(clearButton);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(filterLabel);
        toolbar.add(filterComboBox);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(normalizationLabel);
        toolbar.add(basicMethod);
        toolbar.add(accurateMethod);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(baselineLabel);
        toolbar.add(baselineSpinner);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(progressBar);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(notificationLabel);

        // Request editor
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));

        requestEditor = api.userInterface().createHttpRequestEditor();
        // Don't set initial request - let it stay empty until user loads one
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        // Results panel
        JPanel resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.setBorder(BorderFactory.createTitledBorder("Results"));

        String[] columns = {"URL", "Element Type", "Element Name"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable resultTable = new JTable(tableModel);
        resultTable.setFillsViewportHeight(true);
        resultTable.setRowHeight(25);

        // Add mouse listener for row clicks
        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = resultTable.getSelectedRow();
                if (row >= 0) {
                    HttpRequestResponse pair = requestResponseMap.get(row);
                    if (pair != null) {
                        detailRequestEditor.setRequest(pair.request());
                        detailResponseEditor.setResponse(pair.response());
                    } else {
                        detailRequestEditor.setRequest(null);
                        detailResponseEditor.setResponse(null);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(resultTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        resultsPanel.add(tableScroll, BorderLayout.CENTER);

        // Details panel for request/response
        JPanel detailsPanel = new JPanel(new BorderLayout());
        detailsPanel.setBorder(BorderFactory.createTitledBorder("Details"));

        detailRequestEditor = api.userInterface().createHttpRequestEditor();
        JScrollPane detailRequestScroll = new JScrollPane(detailRequestEditor.uiComponent());
        detailRequestScroll.setBorder(BorderFactory.createTitledBorder("Sent Request"));

        detailResponseEditor = api.userInterface().createHttpResponseEditor();
        JScrollPane detailResponseScroll = new JScrollPane(detailResponseEditor.uiComponent());
        detailResponseScroll.setBorder(BorderFactory.createTitledBorder("Received Response"));

        JSplitPane detailsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, detailRequestScroll, detailResponseScroll);
        detailsSplit.setDividerLocation(300);
        detailsPanel.add(detailsSplit, BorderLayout.CENTER);

        // Combine results and details in a vertical split
        JSplitPane resultsAndDetailsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsPanel, detailsPanel);
        resultsAndDetailsSplit.setDividerLocation(200);

        // Main vertical split
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestPanel, resultsAndDetailsSplit);
        mainSplit.setDividerLocation(200);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("PacketPurifier", mainPanel);
    }

    private void analyzeRequestFromEditor() {
        try {
            HttpRequest modifiedRequest = requestEditor.getRequest();
            
            // Check if there's actually a request loaded
            if (modifiedRequest == null) {
                SwingUtilities.invokeLater(() -> {
                    notificationLabel.setText("No request loaded. Please right-click a request and select 'Send to PacketPurifier'.");
                    new Timer(3000, e -> notificationLabel.setText("")).start();
                });
                return;
            }
            
            // Verify the request has valid content
            if (modifiedRequest.url() == null || modifiedRequest.httpService() == null) {
                SwingUtilities.invokeLater(() -> {
                    notificationLabel.setText("Invalid request: no service found.");
                    new Timer(2000, e -> notificationLabel.setText("")).start();
                });
                return;
            }
            
            // Log request details for debugging
            api.logging().logToOutput("Request loaded successfully: " + modifiedRequest.url());
            api.logging().logToOutput("Request method: " + modifiedRequest.method());
            api.logging().logToOutput("Request service: " + modifiedRequest.httpService());
            
            clearResults(); // Clear results before analyzing
            analyzeRequest(modifiedRequest);
        } catch (Exception e) {
            api.logging().logToError("Error parsing edited request: " + e.getMessage());
            e.printStackTrace();
            SwingUtilities.invokeLater(() -> {
                notificationLabel.setText("Error: " + e.getMessage());
                new Timer(3000, e1 -> notificationLabel.setText("")).start();
            });
        }
    }



    private void clearResults() {
        tableModel.setRowCount(0);
        progressBar.setValue(0);
        progressBar.setString("Ready");
        detailRequestEditor.setRequest(null);
        detailResponseEditor.setResponse(null);
        baselineResponses.clear();
        dynamicLinePrefixesPostfixes.clear();
        dynamicLines.clear();
        requestResponseMap.clear();
        notificationLabel.setText("");
        analyzeButton.setEnabled(true);
        clearButton.setEnabled(true);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            JMenuItem analyzeItem = new JMenuItem("Send to PacketPurifier");
            analyzeItem.addActionListener(e -> loadRequest(event.messageEditorRequestResponse().get().requestResponse().request()));
            menuItems.add(analyzeItem);
        }
        return menuItems;
    }

    private void loadRequest(HttpRequest request) {
        currentRequest = request;
        api.logging().logToOutput("Loading request: " + request.url());
        SwingUtilities.invokeLater(() -> {
            try {
                requestEditor.setRequest(request);
                api.logging().logToOutput("Request set in editor successfully");
            } catch (Exception e) {
                api.logging().logToError("Error setting request in editor: " + e.getMessage());
                e.printStackTrace();
            }
            tableModel.setRowCount(0);
            progressBar.setValue(0);
            progressBar.setString("Ready");
            detailRequestEditor.setRequest(null);
            detailResponseEditor.setResponse(null);
            baselineResponses.clear();
            dynamicLinePrefixesPostfixes.clear();
            dynamicLines.clear();
            requestResponseMap.clear();
            notificationLabel.setText("");
            analyzeButton.setEnabled(true);
            clearButton.setEnabled(true);
        });
    }

    private void analyzeRequest(HttpRequest originalRequest) {
        SwingUtilities.invokeLater(() -> {
            analyzeButton.setEnabled(false);
            clearButton.setEnabled(false);
        });

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

                // Get number of baseline requests from spinner
                int numBaselineRequests = (Integer) baselineSpinner.getValue();
                baselineResponses.clear();
                List<String[]> responseLines = new ArrayList<>();

                // Send baseline requests dynamically
                for (int i = 0; i < numBaselineRequests; i++) {
                    final int requestIndex = i + 1;
                    SwingUtilities.invokeLater(() -> progressBar.setString(String.format("Sending Baseline Request %d/%d", requestIndex, numBaselineRequests)));
                    HttpResponse response = api.http().sendRequest(originalRequest).response();
                    baselineResponses.add(response);
                    responseLines.add(response.toString().split("\n"));
                    Thread.sleep(1500);
                }

                // Reset progress bar for element analysis
                updateProgress(0, totalTasks);

                // Identify dynamic lines
                dynamicLinePrefixesPostfixes.clear();
                dynamicLines.clear();
                int minLines = responseLines.stream().mapToInt(lines -> lines.length).min().orElse(0);
                for (int i = 0; i < minLines; i++) {
                    boolean allEqual = true;
                    String firstLine = responseLines.get(0)[i];
                    for (int j = 1; j < responseLines.size(); j++) {
                        if (!firstLine.equals(responseLines.get(j)[i])) {
                            allEqual = false;
                            break;
                        }
                    }
                    if (!allEqual) {
                        if (accurateMethod.isSelected()) {
                            PrefixPostfixPair pair = extractCommonAndVariable(responseLines, i);
                            dynamicLinePrefixesPostfixes.put(i, pair);
                        } else {
                            dynamicLines.add(i);
                        }
                    }
                }

                // Log normalized lines for the first baseline response
                String[] normalizedLines = baselineResponses.get(0).toString().split("\n");
                if (accurateMethod.isSelected()) {
                    for (Map.Entry<Integer, PrefixPostfixPair> entry : dynamicLinePrefixesPostfixes.entrySet()) {
                        int lineIndex = entry.getKey();
                        PrefixPostfixPair pair = entry.getValue();
                        if (lineIndex < normalizedLines.length) {
                            String originalLine = normalizedLines[lineIndex];
                            String normalizedLine = normalizeLine(originalLine, pair);
                            api.logging().logToOutput(String.format(
                                "Dynamic Line %d: Original='%s', Prefix='%s', Postfix='%s', Normalized='%s'",
                                lineIndex + 1, originalLine, pair.prefix, pair.postfix, normalizedLine
                            ));
                        }
                    }
                } else {
                    for (Integer lineIndex : dynamicLines) {
                        if (lineIndex < normalizedLines.length) {
                            String originalLine = normalizedLines[lineIndex];
                            String normalizedLine = "<__DYNAMIC_CONTENTS__>";
                            api.logging().logToOutput(String.format(
                                "Dynamic Line %d: Original='%s', Normalized='%s'",
                                lineIndex + 1, originalLine, normalizedLine
                            ));
                        }
                    }
                }

                if (filter.equals("All") || filter.equals("Parameters")) {
                    for (HttpParameter param : originalRequest.parameters()) {
                        if (param.type() != HttpParameterType.COOKIE) {
                            HttpRequest modifiedRequest = originalRequest.withRemovedParameters(param);
                            boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, baselineResponses.get(0), "Parameter", param.name(), totalTasks);
                            if (hasImpact) {
                                influentialElements.add(new InfluentialElement("Parameter", param.name()));
                            }
                        }
                    }
                }

                if (filter.equals("All") || filter.equals("Cookies")) {
                    for (HttpParameter cookie : originalRequest.parameters(HttpParameterType.COOKIE)) {
                        HttpRequest modifiedRequest = originalRequest.withRemovedParameters(cookie);
                        boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, baselineResponses.get(0), "Cookie", cookie.name(), totalTasks);
                        if (hasImpact) {
                            influentialElements.add(new InfluentialElement("Cookie", cookie.name()));
                        }
                    }
                }

                if (filter.equals("All") || filter.equals("Headers")) {
                    for (HttpHeader header : originalRequest.headers()) {
                        if (!header.name().equalsIgnoreCase("Host")) {
                            HttpRequest modifiedRequest = originalRequest.withRemovedHeader(header.name());
                            boolean hasImpact = testElementRemoval(originalRequest, modifiedRequest, baselineResponses.get(0), "Header", header.name(), totalTasks);
                            if (hasImpact) {
                                influentialElements.add(new InfluentialElement("Header", header.name()));
                            }
                        }
                    }
                }

                // Create and send minimized packet to Repeater
                HttpRequest minimizedRequest = createMinimizedRequest(originalRequest, influentialElements);
                api.repeater().sendToRepeater(minimizedRequest);

                // Notify user and re-enable buttons
                final int finalTotalTasks = totalTasks;
                SwingUtilities.invokeLater(() -> {
                    updateProgress(finalTotalTasks, finalTotalTasks);
                    notificationLabel.setText("Analysis complete. Minimized packet sent to Repeater.");
                    new Timer(2000, e -> notificationLabel.setText("")).start();
                    analyzeButton.setEnabled(true);
                    clearButton.setEnabled(true);
                });
            } catch (Exception e) {
                api.logging().logToError("Error analyzing request: " + e.getMessage());
                final int finalTotalTasks = tasksRemaining.get();
                SwingUtilities.invokeLater(() -> {
                    tableModel.addRow(new Object[]{
                        originalRequest.url(), "Error", "N/A"
                    });
                    updateProgress(finalTotalTasks, finalTotalTasks);
                    notificationLabel.setText("Error during analysis.");
                    new Timer(2000, e1 -> notificationLabel.setText("")).start();
                    analyzeButton.setEnabled(true);
                    clearButton.setEnabled(true);
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
                    requestResponseMap.put(rowIndex, HttpRequestResponse.httpRequestResponse(modifiedRequest, modifiedResponse));
                });
            }
            return hasImpact;
        } catch (Exception e) {
            api.logging().logToError(String.format("Error testing %s '%s': %s", elementType, elementName, e.getMessage()));
            SwingUtilities.invokeLater(() -> {
                tableModel.addRow(new Object[]{
                    originalRequest.url(), elementType, elementName
                });
                requestResponseMap.put(tableModel.getRowCount() - 1, HttpRequestResponse.httpRequestResponse(modifiedRequest, null));
            });
            return false;
        } finally {
            updateProgress(tasksRemaining.decrementAndGet(), totalTasks);
        }
    }

    private HttpRequest createMinimizedRequest(HttpRequest originalRequest, List<InfluentialElement> influentialElements) {
        HttpRequest minimizedRequest = originalRequest;

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

        for (HttpParameter param : originalRequest.parameters()) {
            if (param.type() != HttpParameterType.COOKIE && !keepParameters.contains(param.name())) {
                minimizedRequest = minimizedRequest.withRemovedParameters(param);
            }
        }

        for (HttpParameter cookie : originalRequest.parameters(HttpParameterType.COOKIE)) {
            if (!keepCookies.contains(cookie.name())) {
                minimizedRequest = minimizedRequest.withRemovedParameters(cookie);
            }
        }

        for (HttpHeader header : originalRequest.headers()) {
            if (!header.name().equalsIgnoreCase("Host") && !keepHeaders.contains(header.name())) {
                minimizedRequest = minimizedRequest.withRemovedHeader(header.name());
            }
        }

        return minimizedRequest;
    }



    private void updateProgress(int remaining, int total) {
        SwingUtilities.invokeLater(() -> {
            int progress = total > 0 ? (int) ((double) (total - remaining) / total * 100) : 100;
            progressBar.setValue(progress);
            progressBar.setString(progress < 100 ? "Analyzing: " + progress + "%" : "Complete");
        });
    }

    private boolean hasSignificantImpact(HttpResponse original, HttpResponse modified) {
        if (original.statusCode() != modified.statusCode()) {
            return true;
        }

        String normalizedOriginal = normalizeResponse(original.toString());
        String normalizedModified = normalizeResponse(modified.toString());
        return !normalizedOriginal.equals(normalizedModified);
    }

    private String normalizeLine(String line, PrefixPostfixPair pair) {
        if (pair != null && line.startsWith(pair.prefix) && line.endsWith(pair.postfix)) {
            int start = pair.prefix.length();
            int end = line.length() - pair.postfix.length();
            if (start <= end) {
                return pair.prefix + "<__DYNAMIC_CONTENTS__>" + pair.postfix;
            }
        }
        return line;
    }

    private String normalizeResponse(String responseStr) {
        String[] lines = responseStr.split("\n");
        if (accurateMethod.isSelected()) {
            for (Map.Entry<Integer, PrefixPostfixPair> entry : dynamicLinePrefixesPostfixes.entrySet()) {
                int lineIndex = entry.getKey();
                if (lineIndex < lines.length) {
                    lines[lineIndex] = normalizeLine(lines[lineIndex], entry.getValue());
                }
            }
        } else {
            for (Integer lineIndex : dynamicLines) {
                if (lineIndex < lines.length) {
                    lines[lineIndex] = "<__DYNAMIC_CONTENTS__>";
                }
            }
        }
        return String.join("\n", lines);
    }

    private PrefixPostfixPair extractCommonAndVariable(List<String[]> responseLines, int lineIndex) {
        String firstLine = responseLines.get(0)[lineIndex];
        int prefixLen = firstLine.length();
        int postfixLen = firstLine.length();

        // Find common prefix
        for (String[] lines : responseLines) {
            String line = lines[lineIndex];
            int commonPrefix = 0;
            while (commonPrefix < Math.min(firstLine.length(), line.length()) &&
                   firstLine.charAt(commonPrefix) == line.charAt(commonPrefix)) {
                commonPrefix++;
            }
            prefixLen = Math.min(prefixLen, commonPrefix);
        }

        // Find common postfix
        for (String[] lines : responseLines) {
            String line = lines[lineIndex];
            int commonPostfix = 0;
            while (commonPostfix < Math.min(firstLine.length() - prefixLen, line.length() - prefixLen) &&
                   firstLine.charAt(firstLine.length() - 1 - commonPostfix) == line.charAt(line.length() - 1 - commonPostfix)) {
                commonPostfix++;
            }
            postfixLen = Math.min(postfixLen, commonPostfix);
        }

        String prefix = firstLine.substring(0, prefixLen);
        String postfix = firstLine.substring(firstLine.length() - postfixLen);
        return new PrefixPostfixPair(prefix, postfix);
    }
}