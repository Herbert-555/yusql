package com.yusql.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.yusql.compare.Normalizer;
import com.yusql.compare.TextSimilarity;
import com.yusql.config.YuSQLConfig;
import com.yusql.engine.ScanEngine;
import com.yusql.filter.FilterManager;
import com.yusql.model.LogEntry;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static burp.api.montoya.core.ByteArray.byteArray;

public class YuSQLTab extends JPanel {
    // Color constants for V5
    private static final Color RED_HIGHLIGHT = new Color(255, 228, 228);
    private static final Color YELLOW_HIGHLIGHT = new Color(255, 255, 200);
    private static final Color BLUE_HIGHLIGHT = new Color(200, 220, 255);
    private static final Color SELECTION_BG = new Color(230, 210, 250);
    private static final Color SELECTION_FG = Color.BLACK;

    private final MontoyaApi api;
    private final ScanEngine engine;
    private final YuSQLConfig config;
    private final FilterManager filterManager;

    // Data stores (matching DouSql pattern exactly)
    public final List<LogEntry> scanResults = Collections.synchronizedList(new ArrayList<>());
    public final List<LogEntry> payloadDetails = Collections.synchronizedList(new ArrayList<>());
    private final List<LogEntry> filteredPayloadCache = new ArrayList<>();

    // Current selection state
    private String currentSelectedScanMd5;
    private LogEntry currentDisplayedItem;

    // Table models
    private ScanResultTableModel scanModel;
    private PayloadDetailTableModel payloadModel;

    // Tables
    private JTable scanTable;
    private JTable payloadTable;

    // Packet counter
    private JLabel packetLabel;
    private javax.swing.Timer packetTimer;

    // HTTP editors
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private Component responseEditorComponent;
    private JTextPane normalizedResponsePane;
    private JPanel responsePanel;
    private JToggleButton normalizedViewToggle;
    private CardLayout responseCardLayout;
    private JPanel responseCardPanel;
    private final HttpService dummyService;

    // Control panel components
    private JCheckBox enableChk, monRepeaterChk, monProxyChk;
    private JCheckBox boolChk, errorChk, orderInjChk, orderChk, negativeChk, numericInjChk, encodeCharsChk;
    private JTextField encodeCharsField;
    private JSpinner threadSp, queueSp;
    private JButton clearBtn;

    // Config tab components
    private JTabbedPane configTabs;
    private final Map<String, JTextArea> configEditors = new HashMap<>();
    private final Map<String, String> configFileNames = new LinkedHashMap<>();

    // UI log area
    private JTextArea logArea;
    private final List<String> logBuffer = new ArrayList<>();

    // Config base dir
    private final Path configDir;

    public YuSQLTab(MontoyaApi api, ScanEngine engine, YuSQLConfig config, FilterManager filterManager) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        this.config = config;
        this.filterManager = filterManager;
        this.configDir = Paths.get(System.getProperty("user.home"), ".yusql");
        this.dummyService = HttpService.httpService("https://localhost:443");

        initConfigFileMap();
        buildUI();
        wireCallbacks();

        // Start engine automatically (checkbox defaults to checked)
        if (enableChk.isSelected()) {
            engine.start();
        }
    }

    private void initConfigFileMap() {
        configFileNames.put("自定义POC", "SQL_error_pocs.ini");
        configFileNames.put("URL黑名单", "SQL_url_blacklist.ini");
        configFileNames.put("域名黑名单", "SQL_domain_blacklist.ini");
        configFileNames.put("域名白名单", "SQL_domain_whitelist.ini");
        configFileNames.put("参数黑名单", "SQL_param_blacklist.ini");
        configFileNames.put("参数白名单", "SQL_param_whitelist.ini");
        configFileNames.put("报错正则", "SQL_diy_error.ini");
        configFileNames.put("去噪正则", "SQL_noise_regex.ini");
    }

    private void buildUI() {
        // Layer 1: Main horizontal split (left 75% / right 25%)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setLeftComponent(buildLeftPanel());
        mainSplitPane.setRightComponent(buildRightPanel());
        mainSplitPane.setDividerLocation(1000);
        mainSplitPane.setResizeWeight(0.75);
        add(mainSplitPane, BorderLayout.CENTER);
    }

    private JComponent buildLeftPanel() {
        // Layer 2a: Vertical split (top 60% / bottom 40%)
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(buildTablesPanel());
        verticalSplit.setBottomComponent(buildEditorsPanel());
        verticalSplit.setDividerLocation(400);
        verticalSplit.setResizeWeight(0.6);
        return verticalSplit;
    }

    private JComponent buildTablesPanel() {
        // Layer 3a: Horizontal split (left 50% / right 50%)
        JSplitPane tablesSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // Left: Scan Results table
        scanModel = new ScanResultTableModel();
        scanTable = new JTable(scanModel);
        setupScanTable();
        JScrollPane scanScroll = new JScrollPane(scanTable);
        JPanel scanPanel = new JPanel(new BorderLayout());
        scanPanel.setBorder(BorderFactory.createTitledBorder("扫描结果"));
        scanPanel.add(scanScroll, BorderLayout.CENTER);

        // Packet counter label
        packetLabel = new JLabel("已发送数据包: 0/0");
        packetLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        packetLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        scanPanel.add(packetLabel, BorderLayout.SOUTH);

        // Timer to refresh packet counter every 500ms
        packetTimer = new javax.swing.Timer(500, e -> {
            packetLabel.setText("已发送数据包: " + engine.getState().getSuccessSent()
                + "/" + engine.getState().getTotalSent());
        });
        packetTimer.start();

        tablesSplit.setLeftComponent(scanPanel);

        // Right: Payload Details table
        payloadModel = new PayloadDetailTableModel();
        payloadTable = new JTable(payloadModel);
        setupPayloadTable();
        JScrollPane payloadScroll = new JScrollPane(payloadTable);
        JPanel payloadPanel = new JPanel(new BorderLayout());
        payloadPanel.setBorder(BorderFactory.createTitledBorder("参数测试详情"));
        payloadPanel.add(payloadScroll, BorderLayout.CENTER);
        tablesSplit.setRightComponent(payloadPanel);

        tablesSplit.setResizeWeight(0.5);
        return tablesSplit;
    }

    private JComponent buildEditorsPanel() {
        // Layer 3b: Horizontal split (left 50% / right 50%)
        JSplitPane editorsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        requestEditor = api.userInterface().createHttpRequestEditor();
        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(BorderFactory.createTitledBorder("原始请求"));
        reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        editorsSplit.setLeftComponent(reqPanel);

        responseEditor = api.userInterface().createHttpResponseEditor();
        responseEditorComponent = responseEditor.uiComponent();
        responsePanel = new JPanel(new BorderLayout());

        // Card layout: switch between raw Burp editor and normalized view
        responseCardLayout = new CardLayout();
        responseCardPanel = new JPanel(responseCardLayout);
        responseCardPanel.add(responseEditorComponent, "raw");
        responseCardPanel.add(createNormalizedResponsePanel(), "normalized");
        responsePanel.add(responseCardPanel, BorderLayout.CENTER);

        // Toggle button bar at top
        normalizedViewToggle = new JToggleButton("归一化视图");
        normalizedViewToggle.addActionListener(e -> {
            if (normalizedViewToggle.isSelected()) {
                responseCardLayout.show(responseCardPanel, "normalized");
                setResponsePanelTitle("归一化响应");
            } else {
                responseCardLayout.show(responseCardPanel, "raw");
                setResponsePanelTitle("原始响应");
            }
        });
        JPanel toggleBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        toggleBar.add(normalizedViewToggle);
        responsePanel.add(toggleBar, BorderLayout.NORTH);

        setResponsePanelTitle("原始响应");
        editorsSplit.setRightComponent(responsePanel);

        editorsSplit.setResizeWeight(0.5);
        return editorsSplit;
    }

    private JComponent buildRightPanel() {
        // Layer 2b: Vertical split (control top / config tabs bottom)
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setTopComponent(buildControlPanel());
        rightSplit.setBottomComponent(buildConfigTabs());
        rightSplit.setDividerLocation(400);
        rightSplit.setResizeWeight(0.0);
        return rightSplit;
    }

    private JComponent buildControlPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.gridx = 0;

        // Title
        gbc.gridy = 0;
        panel.add(new JLabel("YuSQL 2.1.7 - 以下配置会自动保存至配置文件"), gbc);

        // Enable plugin
        enableChk = new JCheckBox("启动插件", true);
        enableChk.addActionListener(e -> {
            if (enableChk.isSelected()) engine.start();
            else engine.stop();
        });
        gbc.gridy = 1; panel.add(enableChk, gbc);

        // Monitor Repeater
        monRepeaterChk = new JCheckBox("监控 Repeater", config.isMonitorRepeater());
        monRepeaterChk.addActionListener(e -> {
            config.setMonitorRepeater(monRepeaterChk.isSelected());
            config.saveSettings();
        });
        gbc.gridy = 2; panel.add(monRepeaterChk, gbc);

        // Monitor Proxy
        monProxyChk = new JCheckBox("监控 Proxy", config.isMonitorProxy());
        monProxyChk.addActionListener(e -> {
            config.setMonitorProxy(monProxyChk.isSelected());
            config.saveSettings();
        });
        gbc.gridy = 3; panel.add(monProxyChk, gbc);

        // Module checkboxes
        boolChk = new JCheckBox("布尔注入（勾选后插件会自动对参数进行该项测试）", config.isEnableBoolean());
        boolChk.addActionListener(e -> config.setEnableBoolean(boolChk.isSelected()));
        gbc.gridy = 4; panel.add(boolChk, gbc);

        errorChk = new JCheckBox("报错注入", config.isEnableError());
        errorChk.addActionListener(e -> config.setEnableError(errorChk.isSelected()));
        gbc.gridy = 5; panel.add(errorChk, gbc);

        orderInjChk = new JCheckBox("排序注入（勾选后插件会自动对参数进行该项测试）", config.isEnableOrderInjection());
        orderInjChk.addActionListener(e -> {
            config.setEnableOrderInjection(orderInjChk.isSelected());
            config.saveSettings();
        });
        gbc.gridy = 6; panel.add(orderInjChk, gbc);

        negativeChk = new JCheckBox("负数测试", config.isEnableNegative());
        negativeChk.addActionListener(e -> config.setEnableNegative(negativeChk.isSelected()));
        gbc.gridy = 7; panel.add(negativeChk, gbc);

        numericInjChk = new JCheckBox("数字型注入", config.isEnableNumericInjection());
        numericInjChk.addActionListener(e -> config.setEnableNumericInjection(numericInjChk.isSelected()));
        gbc.gridy = 8; panel.add(numericInjChk, gbc);

        orderChk = new JCheckBox("追加参数测试", config.isEnableOrder());
        orderChk.addActionListener(e -> config.setEnableOrder(orderChk.isSelected()));
        gbc.gridy = 9; panel.add(orderChk, gbc);
        orderChk.addActionListener(e -> config.setEnableOrder(orderChk.isSelected()));
        gbc.gridy = 8; panel.add(orderChk, gbc);

        // URL encode chars config
        JPanel encodeCharsPn = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        encodeCharsChk = new JCheckBox("URL编码字符", config.isEnableUrlEncodeChars());
        encodeCharsChk.addActionListener(e -> {
            config.setEnableUrlEncodeChars(encodeCharsChk.isSelected());
            config.saveSettings();
        });
        encodeCharsPn.add(encodeCharsChk);
        encodeCharsField = new JTextField(config.getUrlEncodeChars(), 12);
        encodeCharsField.setToolTipText("配置需要额外URL编码的字符，如 {}");
        encodeCharsField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { saveEncodeChars(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { saveEncodeChars(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { saveEncodeChars(); }
        });
        encodeCharsPn.add(encodeCharsField);
        gbc.gridy = 10; panel.add(encodeCharsPn, gbc);

        // Clear button
        clearBtn = new JButton("清空列表并重置扫描器");
        clearBtn.addActionListener(e -> clearAllResults());
        gbc.gridy = 11;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(clearBtn, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Reset config button
        JButton resetConfigBtn = new JButton("重置所有配置");
        resetConfigBtn.addActionListener(e -> {
            int r = JOptionPane.showConfirmDialog(this,
                "确认重置所有配置为默认规则？\n此操作将覆盖所有 .ini 配置文件。",
                "重置配置", JOptionPane.YES_NO_OPTION);
            if (r == JOptionPane.YES_OPTION) {
                config.resetAllConfigs();
                engine.reloadConfig();
                refreshAllConfigEditors();
                appendLog("所有配置已重置为默认规则");
            }
        });
        gbc.gridy = 12;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(resetConfigBtn, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Thread spinner
        gbc.gridy = 13;
        JPanel threadPn = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        threadPn.add(new JLabel("线程数:"));
        threadSp = new JSpinner(new SpinnerNumberModel(config.getThreadCount(), 1, 20, 1));
        threadSp.setPreferredSize(new Dimension(50, 22));
        threadSp.addChangeListener(e -> {
            config.setThreadCount((Integer)threadSp.getValue());
            config.saveSettings();
        });
        threadPn.add(threadSp);
        panel.add(threadPn, gbc);

        // Queue size
        gbc.gridy = 14;
        JPanel queuePn = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        queuePn.add(new JLabel("队列:"));
        queueSp = new JSpinner(new SpinnerNumberModel(config.getMaxQueueSize(), 100, 2000, 100));
        queueSp.setPreferredSize(new Dimension(60, 22));
        queueSp.addChangeListener(e -> {
            config.setMaxQueueSize((Integer)queueSp.getValue());
            config.saveSettings();
        });
        queuePn.add(queueSp);
        panel.add(queuePn, gbc);

        // Spacer
        gbc.gridy = 15;
        gbc.weighty = 1.0;
        panel.add(Box.createVerticalStrut(10), gbc);

        return panel;
    }

    private JComponent buildConfigTabs() {
        configTabs = new JTabbedPane();
        configTabs.setPreferredSize(new Dimension(250, 400));

        // Add config editing tabs
        for (Map.Entry<String,String> entry : configFileNames.entrySet()) {
            JPanel tabPanel = createConfigTab(entry.getValue());
            configTabs.addTab(entry.getKey(), tabPanel);
        }

        // Append params tab (custom split layout)
        configTabs.addTab("追加参数", createAppendParamsTab());

        // Basic settings tab
        configTabs.addTab("基础配置", createBasicSettingsTab());

        // Custom headers tab
        configTabs.addTab("请求头配置", createCustomHeadersTab());

        // Log tab
        configTabs.addTab("日志", createLogTab());

        return configTabs;
    }

    private JPanel createConfigTab(String fileName) {
        JPanel panel = new JPanel(new BorderLayout());
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        configEditors.put(fileName, textArea);

        // Load content
        loadConfigFile(fileName, textArea);

        JScrollPane scroll = new JScrollPane(textArea);
        panel.add(scroll, BorderLayout.CENTER);

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        JButton saveReloadBtn = new JButton("保存并重新加载");
        saveReloadBtn.addActionListener(e -> saveConfigFile(fileName, textArea));
        JButton openFileBtn = new JButton("打开配置文件");
        openFileBtn.addActionListener(e -> {
            Path filePath = configDir.resolve(fileName);
            try { Desktop.getDesktop().open(filePath.toFile()); }
            catch (Exception ex) { /* ignore */ }
        });
        btnPanel.add(saveReloadBtn);
        btnPanel.add(openFileBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        // File label
        JLabel fileLabel = new JLabel("配置文件: " + fileName);
        fileLabel.setFont(new Font("SansSerif", Font.PLAIN, 10));
        panel.add(fileLabel, BorderLayout.NORTH);

        return panel;
    }

    private JPanel createAppendParamsTab() {
        JPanel panel = new JPanel(new BorderLayout());

        // Left: text editor for key:value pairs
        JTextArea appendTextArea = new JTextArea();
        appendTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        // Right: group number spinners per param
        JPanel groupPanel = new JPanel();
        groupPanel.setLayout(new BoxLayout(groupPanel, BoxLayout.Y_AXIS));
        JScrollPane groupScroll = new JScrollPane(groupPanel);
        groupScroll.setPreferredSize(new Dimension(190, 0));

        // Load current content
        loadConfigFile("SQL_append_params.ini", appendTextArea);

        // Map to track spinners by param key
        Map<String, JSpinner> spinnerMap = new LinkedHashMap<>();

        // Parse and populate group spinners
        Runnable refreshGroups = () -> {
            groupPanel.removeAll();
            spinnerMap.clear();
            Map<String, Integer> groups = config.getAppendParamGroups();

            // First pass: count key occurrences and track exact duplicates
            Map<String, Integer> keyCounts = new LinkedHashMap<>();
            Set<String> dupKVs = new HashSet<>();
            Set<String> seenKVs = new HashSet<>();
            for (String line : appendTextArea.getText().split("\\n")) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(':');
                if (idx <= 0) continue;
                String key = line.substring(0, idx).strip();
                String val = line.substring(idx + 1).strip();
                if (key.isEmpty() || val.isEmpty()) continue;
                keyCounts.merge(key, 1, Integer::sum);
                String kv = key + "=" + val;
                if (!seenKVs.add(kv)) dupKVs.add(kv);
            }

            // Second pass: build rows
            Set<String> keyFirstSeen = new HashSet<>();
            for (String line : appendTextArea.getText().split("\\n")) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(':');
                if (idx <= 0) continue;
                String key = line.substring(0, idx).strip();
                String val = line.substring(idx + 1).strip();
                if (key.isEmpty() || val.isEmpty()) continue;

                boolean isDup = keyCounts.getOrDefault(key, 0) > 1;
                String kv = key + "=" + val;
                boolean isExactDup = dupKVs.contains(kv);

                JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
                if (isExactDup) {
                    row.setBackground(new Color(255, 200, 200));
                } else if (isDup) {
                    row.setBackground(RED_HIGHLIGHT);
                }
                JLabel keyLabel = new JLabel(key);
                if (isExactDup) keyLabel.setForeground(Color.GRAY);
                row.add(keyLabel);
                // Order injection checkbox
                Set<String> oiParams = config.getOrderInjectionParams();
                // Default to checked if not explicitly saved (first time)
                boolean oiChecked = oiParams.isEmpty() || oiParams.contains(key);
                JCheckBox oiChk = new JCheckBox("序", oiChecked);
                oiChk.setToolTipText("排序注入测试 — 勾选后该参数参与排序注入");
                oiChk.addActionListener(e -> {
                    Set<String> current2 = new LinkedHashSet<>(config.getOrderInjectionParams());
                    // If all params are currently considered checked (empty set = all default checked),
                    // populate the set with all current params first
                    if (current2.isEmpty()) {
                        for (String line2 : appendTextArea.getText().split("\\n")) {
                            line2 = line2.strip();
                            if (line2.isEmpty() || line2.startsWith("#")) continue;
                            int idx2 = line2.indexOf(':');
                            if (idx2 <= 0) continue;
                            String k2 = line2.substring(0, idx2).strip();
                            String v2 = line2.substring(idx2 + 1).strip();
                            if (!k2.isEmpty() && !v2.isEmpty()) current2.add(k2);
                        }
                    }
                    if (oiChk.isSelected()) current2.add(key);
                    else current2.remove(key);
                    config.saveOrderInjectionParams(current2);
                });
                oiChk.setPreferredSize(new Dimension(40, 20));
                row.add(oiChk);
                int curGroup = groups.getOrDefault(key, 0);
                JSpinner spinner = new JSpinner(new SpinnerNumberModel(curGroup, 0, 99, 1));
                spinner.setPreferredSize(new Dimension(45, 20));
                spinner.setToolTipText(key + "=" + val + " (组" + curGroup + ")" +
                    (isExactDup ? " [重复跳过]" : ""));
                spinner.addChangeListener(e -> {
                    Map<String, Integer> current = new LinkedHashMap<>(config.getAppendParamGroups());
                    int v = (Integer) spinner.getValue();
                    if (v > 0) current.put(key, v);
                    else current.remove(key);
                    config.saveAppendParamGroups(current);
                    engine.reloadConfig();
                    spinner.setToolTipText(key + "=" + val + " (组" + v + ")" +
                        (isExactDup ? " [重复跳过]" : ""));
                });
                spinnerMap.put(key, spinner);
                row.add(spinner);
                groupPanel.add(row);
            }
            groupPanel.revalidate();
            groupPanel.repaint();
        };
        refreshGroups.run();

        // Refresh groups when text changes
        appendTextArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { refreshGroups.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { refreshGroups.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { refreshGroups.run(); }
        });

        // Split pane: left text area, right group spinners
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setLeftComponent(new JScrollPane(appendTextArea));
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("分组(0=同组批量)"));
        rightPanel.add(groupScroll, BorderLayout.CENTER);
        split.setRightComponent(rightPanel);
        split.setResizeWeight(0.65);
        panel.add(split, BorderLayout.CENTER);

        // Bottom buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        JButton saveReloadBtn = new JButton("保存并重新加载");
        saveReloadBtn.addActionListener(e -> {
            try {
                Path filePath = configDir.resolve("SQL_append_params.ini");
                Files.createDirectories(configDir);
                Files.writeString(filePath, appendTextArea.getText(), StandardCharsets.UTF_8);
                appendLog("已保存: SQL_append_params.ini");
                config.loadAllConfigs();
                engine.reloadConfig();
            } catch (Exception ex) {
                appendLog("保存失败: " + ex.getMessage());
            }
        });
        JButton openFileBtn = new JButton("打开配置文件");
        openFileBtn.addActionListener(e -> {
            Path filePath = configDir.resolve("SQL_append_params.ini");
            try { Desktop.getDesktop().open(filePath.toFile()); }
            catch (Exception ex) { /* ignore */ }
        });
        btnPanel.add(saveReloadBtn);
        btnPanel.add(openFileBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        JLabel hint = new JLabel("左侧 key:value，右侧设置分组号。同组参数批量追加，0=默认组。");
        hint.setFont(new Font("SansSerif", Font.PLAIN, 10));
        panel.add(hint, BorderLayout.NORTH);

        return panel;
    }

    private JPanel createBasicSettingsTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        // Simple scrollable settings
        JTextArea area = new JTextArea();
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setEditable(false);
        area.setText("基础配置通过 SQL_settings.ini 文件管理。\n\n"
            + "线程数: " + config.getThreadCount() + "\n"
            + "最大队列: " + config.getMaxQueueSize() + "\n"
            + "相似度阈值: " + config.getSimilarityThreshold() + "\n"
            + "长度差异绝对值: " + config.getLengthDiffAbs() + "\n"
            + "长度差异比例: " + config.getLengthDiffRatio() + "\n\n"
            + "使用右侧各配置Tab编辑具体规则。");
        JScrollPane scroll = new JScrollPane(area);
        panel.add(scroll);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton openDirBtn = new JButton("打开配置目录");
        openDirBtn.addActionListener(e -> {
            try { Runtime.getRuntime().exec("explorer " + configDir.toString()); }
            catch (Exception ex) { /* ignore */ }
        });
        JButton reloadBtn = new JButton("重新加载配置");
        reloadBtn.addActionListener(e -> {
            config.loadAllConfigs();
            engine.reloadConfig();
            appendLog("配置已重新加载");
        });
        btnPanel.add(openDirBtn);
        btnPanel.add(reloadBtn);
        panel.add(btnPanel);
        return panel;
    }

    private JPanel createCustomHeadersTab() {
        String fileName = "SQL_custom_headers.ini";
        JPanel panel = new JPanel(new BorderLayout());
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        loadConfigFile(fileName, textArea);

        JScrollPane scroll = new JScrollPane(textArea);
        panel.add(scroll, BorderLayout.CENTER);

        JLabel hint = new JLabel("每行一个请求头，格式: Header-Name: value（如 Range: bytes=0-1000）");
        hint.setFont(new Font("SansSerif", Font.PLAIN, 10));
        panel.add(hint, BorderLayout.NORTH);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 2));
        JButton saveReloadBtn = new JButton("保存并重新加载");
        saveReloadBtn.addActionListener(e -> {
            try {
                Files.createDirectories(configDir);
                Path filePath = configDir.resolve(fileName);
                Files.writeString(filePath, textArea.getText(), StandardCharsets.UTF_8);
                appendLog("已保存: " + fileName);
                config.loadAllConfigs();
                engine.reloadConfig();
            } catch (Exception ex) {
                appendLog("保存失败 " + fileName + ": " + ex.getMessage());
            }
        });
        JButton openFileBtn = new JButton("打开配置文件");
        openFileBtn.addActionListener(e -> {
            Path filePath = configDir.resolve(fileName);
            try { Desktop.getDesktop().open(filePath.toFile()); }
            catch (Exception ex) { /* ignore */ }
        });
        btnPanel.add(saveReloadBtn);
        btnPanel.add(openFileBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createLogTab() {
        JPanel panel = new JPanel(new BorderLayout());
        logArea = new JTextArea();
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);
        panel.add(scroll, BorderLayout.CENTER);
        // Flush any buffered logs
        appendLog("日志系统初始化完成");
        return panel;
    }

    public void appendLog(String msg) {
        String timestamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
        String line = "[" + timestamp + "] " + msg;
        if (logArea == null) {
            synchronized (logBuffer) { logBuffer.add(line); }
            return;
        }
        SwingUtilities.invokeLater(() -> {
            synchronized (logBuffer) {
                for (String buffered : logBuffer) {
                    logArea.append(buffered + "\n");
                }
                logBuffer.clear();
            }
            logArea.append(line + "\n");
            int lines = logArea.getLineCount();
            if (lines > 5000) {
                try {
                    int end = logArea.getLineEndOffset(lines - 5000);
                    logArea.replaceRange("", 0, end);
                } catch (Exception ignore) {}
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void loadConfigFile(String fileName, JTextArea area) {
        try {
            Path filePath = configDir.resolve(fileName);
            if (Files.exists(filePath)) {
                area.setText(Files.readString(filePath, StandardCharsets.UTF_8));
            } else {
                area.setText("# " + fileName + "\n# 文件不存在，将在保存时创建\n");
            }
        } catch (Exception e) {
            area.setText("# 加载失败: " + e.getMessage() + "\n");
        }
    }

    private void saveConfigFile(String fileName, JTextArea area) {
        try {
            Files.createDirectories(configDir);
            Path filePath = configDir.resolve(fileName);
            Files.writeString(filePath, area.getText(), StandardCharsets.UTF_8);
            appendLog("已保存: " + fileName);
            // Reload config if it affects engine
            config.loadAllConfigs();
            engine.reloadConfig();
        } catch (Exception e) {
            appendLog("保存失败 " + fileName + ": " + e.getMessage());
        }
    }

    // --- Table setup ---
    private void setupScanTable() {
        scanTable.setSelectionBackground(SELECTION_BG);
        scanTable.setSelectionForeground(SELECTION_FG);
        scanTable.getTableHeader().setReorderingAllowed(false);
        scanTable.setRowHeight(22);

        // Column widths
        scanTable.getColumnModel().getColumn(0).setPreferredWidth(35);  // #
        scanTable.getColumnModel().getColumn(1).setPreferredWidth(60);  // 来源
        scanTable.getColumnModel().getColumn(2).setPreferredWidth(300); // URL
        scanTable.getColumnModel().getColumn(3).setPreferredWidth(80);  // 返回包长度
        scanTable.getColumnModel().getColumn(4).setPreferredWidth(80);  // 状态

        // Row click → show original req/resp, filter payload table
        scanTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = scanTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = scanTable.convertRowIndexToModel(row);
            if (modelRow >= 0 && modelRow < scanResults.size()) {
                LogEntry entry = scanResults.get(modelRow);
                updatePayloadDetailsForEntry(entry);
                updateEditorsForScan(entry);
            }
        });

        // Custom renderer for color-coded rows
        scanTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (isSelected) {
                    c.setBackground(SELECTION_BG);
                    c.setForeground(SELECTION_FG);
                } else {
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < scanResults.size()) {
                        LogEntry entry = scanResults.get(modelRow);
                        Color bg = getColorForLevel(entry.getColorLevel());
                        c.setBackground(bg != null ? bg : Color.WHITE);
                    }
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        });

        // Right-click context menu
        scanTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showScanContextMenu(e);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showScanContextMenu(e);
            }
        });
    }

    private void setupPayloadTable() {
        payloadTable.setSelectionBackground(SELECTION_BG);
        payloadTable.setSelectionForeground(SELECTION_FG);
        payloadTable.getTableHeader().setReorderingAllowed(false);
        payloadTable.setRowHeight(22);

        // Column widths
        payloadTable.getColumnModel().getColumn(0).setPreferredWidth(120); // 参数
        payloadTable.getColumnModel().getColumn(1).setPreferredWidth(100); // payload
        payloadTable.getColumnModel().getColumn(2).setPreferredWidth(80);  // 返回包长度
        payloadTable.getColumnModel().getColumn(3).setPreferredWidth(120); // 变化
        payloadTable.getColumnModel().getColumn(4).setPreferredWidth(50);  // 用时
        payloadTable.getColumnModel().getColumn(5).setPreferredWidth(50);  // 响应码
        payloadTable.getColumnModel().getColumn(6).setPreferredWidth(60);  // 相似度
        payloadTable.getColumnModel().getColumn(7).setPreferredWidth(70);  // 测试类型

        // Row click → show test req/resp
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = payloadTable.getSelectedRow();
            if (row < 0) return;
            List<LogEntry> filtered = getFilteredPayloadDetails();
            int modelRow = payloadTable.convertRowIndexToModel(row);
            if (modelRow >= 0 && modelRow < filtered.size()) {
                LogEntry entry = filtered.get(modelRow);
                updateEditorsForPayload(entry);
            }
        });

        // Custom renderer for color-coded rows
        payloadTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                if (isSelected) {
                    c.setBackground(SELECTION_BG);
                    c.setForeground(SELECTION_FG);
                } else {
                    List<LogEntry> list = getFilteredPayloadDetails();
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < list.size()) {
                        LogEntry entry = list.get(modelRow);
                        Color bg = getColorForLevel(entry.getColorLevel());
                        c.setBackground(bg != null ? bg : Color.WHITE);
                    }
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        });

        // Right-click context menu
        payloadTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showPayloadContextMenu(e);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showPayloadContextMenu(e);
            }
        });
    }

    private void showScanContextMenu(MouseEvent e) {
        int row = scanTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        int modelRow = scanTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= scanResults.size()) return;
        LogEntry entry = scanResults.get(modelRow);

        JPopupMenu popup = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("删除此接口");
        deleteItem.addActionListener(ae -> {
            // Remove payload details with matching MD5
            synchronized (payloadDetails) {
                payloadDetails.removeIf(p -> p.getDataMd5().equals(entry.getDataMd5()));
            }
            scanResults.remove(modelRow);
            scanModel.fireTableDataChanged();
            payloadModel.fireTableDataChanged();
            // Clear editors if this was selected
            if (entry.getDataMd5().equals(currentSelectedScanMd5)) {
                currentSelectedScanMd5 = null;
                currentDisplayedItem = null;
                refreshFilteredPayloadCache();
                requestEditor.setRequest(HttpRequest.httpRequest(dummyService, byteArray(new byte[0])));
                responseEditor.setResponse(HttpResponse.httpResponse(byteArray(new byte[0])));
                clearNormalizedResponse();
            }
        });
        popup.add(deleteItem);
        popup.show(scanTable, e.getX(), e.getY());
    }

    private void showPayloadContextMenu(MouseEvent e) {
        int row = payloadTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        List<LogEntry> filtered = getFilteredPayloadDetails();
        int modelRow = payloadTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= filtered.size()) return;
        LogEntry entry = filtered.get(modelRow);

        JPopupMenu popup = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("删除此记录");
        deleteItem.addActionListener(ae -> {
            payloadDetails.remove(entry);
            filteredPayloadCache.remove(entry);
            payloadModel.fireTableDataChanged();
            // Recalculate scan entry color
            recalcScanEntryColor(entry.getDataMd5());
        });
        popup.add(deleteItem);
        popup.show(payloadTable, e.getX(), e.getY());
    }

    private JComponent createNormalizedResponsePanel() {
        if (normalizedResponsePane == null) {
            normalizedResponsePane = new JTextPane();
            normalizedResponsePane.setEditable(false);
            normalizedResponsePane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        }
        return new JScrollPane(normalizedResponsePane);
    }

    private static final java.util.regex.Pattern NOISE_TAG_RE =
        java.util.regex.Pattern.compile("<(UUID|HEX|TS|DATETIME|JWT|TOKEN|SESSION|NOISE)>");

    private void updateNormalizedResponse(byte[] responseBytes) {
        if (normalizedResponsePane == null) return;
        if (responseBytes == null || responseBytes.length == 0) {
            clearNormalizedResponse();
            return;
        }
        try {
            HttpResponse response = HttpResponse.httpResponse(byteArray(responseBytes));
            String body = response.bodyToString();
            String normalizedBody = createCurrentNormalizer().normalize(body);

            StyledDocument doc = normalizedResponsePane.getStyledDocument();
            // Default style
            Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
            StyleConstants.setFontFamily(def, Font.MONOSPACED);
            StyleConstants.setFontSize(def, 12);

            // Highlight style for replaced noise tags
            Style hl = doc.addStyle("hl", def);
            StyleConstants.setBackground(hl, new Color(255, 255, 0)); // yellow
            StyleConstants.setBold(hl, true);

            doc.remove(0, doc.getLength());
            int lastEnd = 0;
            java.util.regex.Matcher m = NOISE_TAG_RE.matcher(normalizedBody);
            while (m.find()) {
                if (m.start() > lastEnd) {
                    doc.insertString(doc.getLength(), normalizedBody.substring(lastEnd, m.start()), def);
                }
                doc.insertString(doc.getLength(), m.group(), hl);
                lastEnd = m.end();
            }
            if (lastEnd < normalizedBody.length()) {
                doc.insertString(doc.getLength(), normalizedBody.substring(lastEnd), def);
            }
        } catch (Exception e) {
            clearNormalizedResponse();
        }
    }

    private void clearNormalizedResponse() {
        if (normalizedResponsePane != null) normalizedResponsePane.setText("");
    }

    private Normalizer createCurrentNormalizer() {
        Normalizer normalizer = new Normalizer();
        normalizer.setNoise(config.getNoisePatterns());
        normalizer.setRemoveWs(config.isRemoveWhitespace());
        return normalizer;
    }


    private String calculateSimilarityDisplay(LogEntry entry) {
        byte[] baseResponse = findScanResponse(entry.getDataMd5());
        byte[] testResponse = entry.getResponse();
        if (baseResponse == null || testResponse == null) return "";
        try {
            Normalizer normalizer = createCurrentNormalizer();
            String baseBody = normalizer.normalize(HttpResponse.httpResponse(byteArray(baseResponse)).bodyToString());
            String testBody = normalizer.normalize(HttpResponse.httpResponse(byteArray(testResponse)).bodyToString());
            int percent = (int) Math.round(TextSimilarity.levenshteinRatio(baseBody, testBody) * 100);
            if (percent < 0) percent = 0;
            if (percent > 100) percent = 100;
            return percent + "%";
        } catch (Exception e) {
            return "";
        }
    }

    private byte[] findScanResponse(String dataMd5) {
        if (dataMd5 == null) return null;
        synchronized (scanResults) {
            for (LogEntry entry : scanResults) {
                if (dataMd5.equals(entry.getDataMd5())) return entry.getResponse();
            }
        }
        return null;
    }

    private void setResponsePanelTitle(String title) {
        if (responsePanel != null) responsePanel.setBorder(BorderFactory.createTitledBorder(title));
    }

    private void updatePayloadDetailsForEntry(LogEntry scanEntry) {
        currentSelectedScanMd5 = scanEntry.getDataMd5();
        refreshFilteredPayloadCache();
        payloadModel.fireTableDataChanged();
    }

    private void updateEditorsForScan(LogEntry entry) {
        currentDisplayedItem = entry;
        if (entry.getRequest() != null) {
            requestEditor.setRequest(HttpRequest.httpRequest(getService(entry), byteArray(entry.getRequest())));
            ((JPanel)((JComponent)requestEditor.uiComponent()).getParent()).setBorder(
                BorderFactory.createTitledBorder("原始请求"));
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(dummyService, byteArray(new byte[0])));
        }
        if (entry.getResponse() != null) {
            responseEditor.setResponse(HttpResponse.httpResponse(byteArray(entry.getResponse())));
            updateNormalizedResponse(entry.getResponse());
            setResponsePanelTitle("原始响应");
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(byteArray(new byte[0])));
            clearNormalizedResponse();
        }
    }

    private void updateEditorsForPayload(LogEntry entry) {
        currentDisplayedItem = entry;
        if (entry.getRequest() != null) {
            requestEditor.setRequest(HttpRequest.httpRequest(getService(entry), byteArray(entry.getRequest())));
            ((JPanel)((JComponent)requestEditor.uiComponent()).getParent()).setBorder(
                BorderFactory.createTitledBorder("测试请求"));
        }
        if (entry.getResponse() != null) {
            responseEditor.setResponse(HttpResponse.httpResponse(byteArray(entry.getResponse())));
            updateNormalizedResponse(entry.getResponse());
            setResponsePanelTitle("测试响应");
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(byteArray(new byte[0])));
            clearNormalizedResponse();
        }
    }

    /** Build HttpService from LogEntry's stored host/port/secure, or fall back to dummy */
    private HttpService getService(LogEntry entry) {
        if (entry.getServiceHost() != null && !entry.getServiceHost().isEmpty()) {
            return HttpService.httpService(entry.getServiceHost(), entry.getServicePort(), entry.isServiceSecure());
        }
        return dummyService;
    }

    // --- Color helpers ---
    private Color getColorForLevel(int level) {
        return switch(level) {
            case 3 -> RED_HIGHLIGHT;
            case 2 -> YELLOW_HIGHLIGHT;
            case 1 -> BLUE_HIGHLIGHT;
            default -> null;
        };
    }

    private void recalcScanEntryColor(String md5) {
        // Find max color level among payload children
        int maxLevel = 0;
        synchronized (payloadDetails) {
            for (LogEntry p : payloadDetails) {
                if (p.getDataMd5().equals(md5)) {
                    if (p.getColorLevel() > maxLevel) maxLevel = p.getColorLevel();
                }
            }
        }
        // Update scan entry state and color
        synchronized (scanResults) {
            for (LogEntry s : scanResults) {
                if (s.getDataMd5().equals(md5)) {
                    s.setColorLevel(maxLevel);
                    s.setState(switch(maxLevel) {
                        case 3 -> "报错命中";
                        case 2 -> "布尔命中";
                        case 1 -> "疑似变化";
                        default -> "已完成";
                    });
                    break;
                }
            }
        }
        SwingUtilities.invokeLater(() -> scanModel.fireTableDataChanged());
    }

    // --- Wire engine callbacks ---
    private void wireCallbacks() {
        engine.setScanStartCallback(entry -> {
            scanResults.add(entry);
            SwingUtilities.invokeLater(() -> {
                scanModel.fireTableDataChanged();
                // Auto-select the new row
                int idx = scanResults.size() - 1;
                scanTable.setRowSelectionInterval(idx, idx);
            });
        });

        // Update callback: updates an existing scan entry's state/color/length/response
        engine.setScanUpdateCallback(entry -> {
            synchronized (scanResults) {
                for (int i = 0; i < scanResults.size(); i++) {
                    if (scanResults.get(i).getDataMd5().equals(entry.getDataMd5())) {
                        // "跳过" state means remove from UI entirely
                        if ("跳过".equals(entry.getState())) {
                            scanResults.remove(i);
                        } else {
                            LogEntry target = scanResults.get(i);
                            if (entry.getState() != null) target.setState(entry.getState());
                            if (entry.getColorLevel() >= 0) target.setColorLevel(entry.getColorLevel());
                            if (entry.getResponseLength() > 0) target.setResponseLength(entry.getResponseLength());
                            if (entry.getResponse() != null) target.setResponse(entry.getResponse());
                            if (entry.getRequest() != null) target.setRequest(entry.getRequest());
                        }
                        break;
                    }
                }
            }
            SwingUtilities.invokeLater(() -> scanModel.fireTableDataChanged());
        });

        engine.setPayloadResultCallback(entry -> {
            entry.setSimilarity(calculateSimilarityDisplay(entry));
            payloadDetails.add(entry);
            SwingUtilities.invokeLater(() -> {
                if (currentSelectedScanMd5 == null || currentSelectedScanMd5.equals(entry.getDataMd5())) {
                    filteredPayloadCache.add(entry);
                }
                payloadModel.fireTableDataChanged();
                recalcScanEntryColor(entry.getDataMd5());
            });
        });

        engine.setScanCompleteCallback(entry -> {
            synchronized (scanResults) {
                for (int i = 0; i < scanResults.size(); i++) {
                    if (scanResults.get(i).getDataMd5().equals(entry.getDataMd5())) {
                        LogEntry target = scanResults.get(i);
                        target.setState(entry.getState());
                        target.setColorLevel(entry.getColorLevel());
                        target.setResponseLength(entry.getResponseLength());
                        if (entry.getResponse() != null) target.setResponse(entry.getResponse());
                        if (entry.getRequest() != null) target.setRequest(entry.getRequest());
                        break;
                    }
                }
            }
            SwingUtilities.invokeLater(() -> scanModel.fireTableDataChanged());
        });

        engine.setLogCallback(msg -> {
            appendLog(msg);
        });
        appendLog("Log callback wired to engine");
    }

    // --- Public helper ---
    private List<LogEntry> getFilteredPayloadDetails() {
        return filteredPayloadCache;
    }

    private void refreshFilteredPayloadCache() {
        filteredPayloadCache.clear();
        synchronized (payloadDetails) {
            if (currentSelectedScanMd5 == null) {
                filteredPayloadCache.addAll(payloadDetails);
                return;
            }
            for (LogEntry entry : payloadDetails) {
                if (currentSelectedScanMd5.equals(entry.getDataMd5())) {
                    filteredPayloadCache.add(entry);
                }
            }
        }
    }

    public void clearAllResults() {
        // 停止引擎并清空任务队列
        if (engine.isRunning()) {
            engine.stop();
        }
        engine.getQueue().clear();
        engine.getDedup().clearAll();
        engine.getState().reset();
        // 清空 UI 数据
        scanResults.clear();
        payloadDetails.clear();
        filteredPayloadCache.clear();
        currentSelectedScanMd5 = null;
        currentDisplayedItem = null;
        LogEntry.resetIdCounter();
        SwingUtilities.invokeLater(() -> {
            scanModel.fireTableDataChanged();
            payloadModel.fireTableDataChanged();
            requestEditor.setRequest(HttpRequest.httpRequest(dummyService, byteArray(new byte[0])));
            responseEditor.setResponse(HttpResponse.httpResponse(byteArray(new byte[0])));
            clearNormalizedResponse();
        });
    }

    private void saveEncodeChars() {
        config.setUrlEncodeChars(encodeCharsField.getText());
        config.saveSettings();
        engine.reloadConfig();
    }

    public void clearDedupCache() {
        engine.getDedup().clearAll();
    }

    private void refreshAllConfigEditors() {
        for (var entry : configEditors.entrySet()) {
            loadConfigFile(entry.getKey(), entry.getValue());
        }
    }

    // --- Inner table model classes ---

    class ScanResultTableModel extends AbstractTableModel {
        private final String[] cols = {"#", "来源", "URL", "返回包长度", "状态"};

        @Override public int getRowCount() { return scanResults.size(); }
        @Override public int getColumnCount() { return 5; }
        @Override public String getColumnName(int col) { return cols[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            synchronized (scanResults) {
                if (row >= scanResults.size()) return "";
                LogEntry e = scanResults.get(row);
                return switch(col) {
                    case 0 -> e.getId();
                    case 1 -> e.getToolName();
                    case 2 -> e.getUrl();
                    case 3 -> e.getResponseLength();
                    case 4 -> e.getState();
                    default -> "";
                };
            }
        }
    }

    class PayloadDetailTableModel extends AbstractTableModel {
        private final String[] cols = {"参数", "payload", "返回包长度", "变化", "用时", "响应码", "相似度", "测试类型"};

        @Override public int getRowCount() { return getFilteredPayloadDetails().size(); }
        @Override public int getColumnCount() { return 8; }
        @Override public String getColumnName(int col) { return cols[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            List<LogEntry> list = getFilteredPayloadDetails();
            if (row >= list.size()) return "";
            LogEntry e = list.get(row);
            return switch(col) {
                case 0 -> e.getParameter();
                case 1 -> e.getDisplayPayload();
                case 2 -> e.getResponseLength();
                case 3 -> e.getChange();
                case 4 -> e.getResponseTime();
                case 5 -> e.getStatusCode();
                case 6 -> e.getSimilarity();
                case 7 -> e.getTestType();
                default -> "";
            };
        }
    }

}
