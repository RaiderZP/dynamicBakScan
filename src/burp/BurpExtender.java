package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;
    private String ExtenderName = "dynamicBakScan";

    private JPanel jPanel1;
    private JTabbedPane sunTabs;
    private JTextField targetUrl_text;

    private ArrayList<String> detect_url; //测试url

    private ArrayList<String> dirname = new ArrayList<>(); //测试url

//    private List<TablesData> Udatas = new ArrayList<>();


    private static BufferedReader readUsingBufferedReader(String fileName) throws IOException {
        File file = new File(fileName);
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);
        br.mark((int)file.length()+1);
        return br;
    }

    private void  bakupDetect(String new_url,List<IScanIssue> issues,IHttpService httpService,IExtensionHelpers helpers,ArrayList<Integer> list,IHttpRequestResponse messageInfo,IBurpExtenderCallbacks callbacks) throws MalformedURLException {
        URL url = new URL(new_url);

        byte[] req  = helpers.buildHttpRequest(url);

        IHttpRequestResponse repdata = callbacks.makeHttpRequest(messageInfo.getHttpService(),req);


        //获取新发送数据包的状态码以及数据包长度
        IResponseInfo analyzedResponse1 = helpers.analyzeResponse(repdata.getResponse());
        int code = analyzedResponse1.getStatusCode();

        if (code == 200){
            byte[] res = repdata.getResponse();
            String resp = new String(res);

//            stdout.println(resp);
            int len = resp.length();


            if(!list.contains(len)){ //如果存在长度一致的备份文件，则可能为waf，只输出长度不同的文件
//                    stdout.println(url  + " exist bakup");
                issues.add(new CustomScanIssue(
                        httpService,
                        url,
                        new IHttpRequestResponse[]{repdata},
                        "bakup file finded",
                        "bakup file by :" + new_url + "," + "response_len is " + len,
                        "High",
                        "Tentative"
                ));
            }

            list.add(len);

        }

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println(ExtenderName + " by blacklist^Ping");
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerScannerCheck(this);


        SwingUtilities.invokeLater(new Runnable() { //建立ui界面,可添加测试url
            public void run() {
                sunTabs = new JTabbedPane();
                jPanel1 = new JPanel();

                GridBagLayout gridBagLayout = new GridBagLayout();
                gridBagLayout.columnWidths = new int[]{30, 0, 30, 101, 221, 0, 0, 0};
                gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
                gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
                jPanel1.setLayout(gridBagLayout);


                JLabel lblPathRegex = new JLabel("Target_Url:");
                GridBagConstraints gbc_lblPathRegex = new GridBagConstraints();
                gbc_lblPathRegex.anchor = GridBagConstraints.EAST;
                gbc_lblPathRegex.insets = new Insets(3, 1, 3, 1);
                gbc_lblPathRegex.gridx = 2;
                gbc_lblPathRegex.gridy = 3;
                jPanel1.add(lblPathRegex, gbc_lblPathRegex);


                targetUrl_text = new JTextField();
                GridBagConstraints gbc_pathRegEx = new GridBagConstraints();
                gbc_pathRegEx.insets = new Insets(3, 0, 3, 0);
                gbc_pathRegEx.gridx = 4;
                gbc_pathRegEx.gridy = 3;
                jPanel1.add(targetUrl_text, gbc_pathRegEx);
                targetUrl_text.setColumns(50);

                JButton btn1 = new JButton("Save configuration");
                GridBagConstraints gbc_btn1 = new GridBagConstraints();
                gbc_btn1.gridx = 2;
                gbc_btn1.gridy = 6;
                jPanel1.add(btn1, gbc_btn1);

                btn1.addMouseListener(new MouseAdapter() {
                    public void mouseClicked(MouseEvent e) {
                        detect_url = new ArrayList(); //每次点击重置数组
                        String text = targetUrl_text.getText();
                        String[] strArray = text.split(";");
//                        detect_url.add(text);
                        for (int i = 0; i < strArray.length; i++)
//                            stdout.println(strArray[i]);
                            detect_url.add(strArray[i]);
                    }

                });


                sunTabs.add("config", jPanel1);
//                topTabs.add("run");

                callbacks.customizeUiComponent(sunTabs);

//                helper.UIStuff.updateJCheckBoxBackground(jPanel1);
                //将自定义的标签页添加到Burp UI 中
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse messageInfo) throws IOException {


        IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
//        对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。


        /*****************获取url**********************/
        URL url = analyzeRequest.getUrl();
//        stdout.println("url:" + url);

        ArrayList<Integer> list = new ArrayList<>(); //保存返回包长度，以便判断注入是否成功
        ArrayList<IHttpRequestResponse> resps = new ArrayList<>(); //保存数据包对象，在发送成功漏洞报告时进行调用
        ArrayList<Integer> codes = new ArrayList<>(); //保存状态码信息，用于判断注入是否成功
        IHttpService httpService;
        httpService = messageInfo.getHttpService();

        String fileName = "D:/dic/bak.txt"; //payload字典

        //判断url中的域名是否在测试名单中
        Boolean j = false;
        if (detect_url.size() > 0) {
            for (int i = 0; i < detect_url.size(); i++) {
                if (url.toString().contains(detect_url.get(i)))
                    j = true;
            }
            if(j == false){  //没有匹配到url名单时返回null进行退出
                return null;
            }
        }



        String urls = url.toString();

        // 判断是否存在参数，并去除参数
        int site = urls.indexOf('?');
        if(site != -1){
            String[] urlsArray = urls.split("\\?");
            urls = urlsArray[0];
        }

        String[] strArray = urls.split("/");


        String line;
        BufferedReader br = readUsingBufferedReader(fileName);

        List<IScanIssue> issues = new ArrayList<>(1);

        for (int i = 3; i < strArray.length; i++){ //从3开始，舍弃掉前面无用的http和域名部分

            if(strArray[i].indexOf(".") == -1){ //判断是否存在后缀，只对目录名进行备份扫描
                if(!(dirname.contains(strArray[i]))){ //判断是否重复测试
                    int end1 = urls.indexOf(strArray[i]);
                    int end2 = urls.indexOf(strArray[i]) + strArray[i].length();
                    String url_start1 = urls.substring(0,end1);
                    String url_start2 = urls.substring(0,end2);

                    br.reset();
                    while ((line = br.readLine()) != null) {
                        String new_url1 = url_start1 + strArray[i] + "." + line;
                        String new_url2 = url_start2 + "/" + strArray[i] + "." + line;

                        bakupDetect(new_url1, issues, httpService, helpers, list, messageInfo, callbacks);
                        bakupDetect(new_url2, issues, httpService, helpers, list, messageInfo, callbacks);

                        if (i > 3) {

                            int end3 = urls.indexOf(strArray[3]);
                            String url_start3 = urls.substring(0, end3);
                            String new_url3 = url_start3 + strArray[i] + "." + line;
                            bakupDetect(new_url3, issues, httpService, helpers, list, messageInfo, callbacks);
                        }
                    }
                    dirname.add(strArray[i]);


                };
            };
        }

        br.close();

        return issues;
    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse messageInfo, IScannerInsertionPoint
            insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getConfidence().equals(newIssue.getConfidence()) && existingIssue.getSeverity().equals(newIssue.getSeverity()))
            return -1;
        else return 0;
    }


    @Override
    public String getTabCaption() {
        return "bakDetect";
    }

    @Override
    public Component getUiComponent() {
        return sunTabs;
    }


}


class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String certain;

    /**
     * @param httpService  HTTP服务
     * @param url          漏洞url
     * @param httpMessages HTTP消息
     * @param name         漏洞名称
     * @param detail       漏洞细节
     * @param severity     漏洞等级
     */
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String certain) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.certain = certain;
    }

    public URL getUrl() {
        return url;
    }

    public String getIssueName() {
        return name;
    }

    public int getIssueType() {
        return 0;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return certain;
    }

    public String getIssueBackground() {
        return null;
    }

    public String getRemediationBackground() {
        return null;
    }

    public String getIssueDetail() {
        return detail;
    }

    public String getRemediationDetail() {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    public IHttpService getHttpService() {
        return httpService;
    }
}
