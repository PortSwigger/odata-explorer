from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JSplitPane, BoxLayout
from java.awt import BorderLayout, Dimension
import javax.swing.JOptionPane as JOptionPane
import xml.dom.minidom as minidom

from java.awt.event import ActionListener



class ButtonClickListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        metadata_text = self.extender.metadata_area.getText()
        #self.extender.result_area.setText(metadata_text)
        self.extender.result_area.setText(self.extender.generate_requests(metadata_text))

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("OData Tab")
        self.init_gui()
        callbacks.addSuiteTab(self)

    def init_gui(self):
        self.main_panel = JPanel(BorderLayout())

        self.generate_button = JButton("Generate Requests")
        button_click_listener = ButtonClickListener(self)
        self.generate_button.addActionListener(button_click_listener)
        self.main_panel.add(self.generate_button, BorderLayout.NORTH)


        self.content_panel = JPanel()
        self.content_panel.setLayout(BoxLayout(self.content_panel, BoxLayout.X_AXIS))
        self.main_panel.add(self.content_panel, BorderLayout.CENTER)

        self.metadata_area = JTextArea("Insert metadata XML here!")
        self.metadata_area.setWrapStyleWord(True)
        self.metadata_scroll = JScrollPane(self.metadata_area)
        self.metadata_scroll.setPreferredSize(Dimension(400, 200))
        self.content_panel.add(self.metadata_scroll)

        self.result_area = JTextArea()
        self.result_area.setWrapStyleWord(True)
        self.result_area.setEditable(True)
        self.result_scroll = JScrollPane(self.result_area)
        self.result_scroll.setPreferredSize(Dimension(400, 200))
        self.content_panel.add(self.result_scroll)

    def generate_requests(self, raw):
        return raw

    def getTabCaption(self):
        return "OData Extractor"

    def getUiComponent(self):
        return self.main_panel

