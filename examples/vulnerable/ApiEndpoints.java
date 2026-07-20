package com.example.vuln;

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.naming.directory.InitialDirContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

@RestController
public class ApiEndpoints {

    @GetMapping("/search")
    public String ldapSearch(@RequestParam String username) throws Exception {
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", "(uid=" + username + ")", null);
        return "ok";
    }

    @GetMapping("/xpath")
    public String xpathQuery(@RequestParam String id) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.compile("//user[@id='" + id + "']");
        return "ok";
    }

    @GetMapping("/calc")
    public Object spel(@RequestParam String expr) {
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expr).getValue();
    }

    @PostMapping("/eval")
    public Object runScript(@RequestParam String script) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(script);
    }

    @PostMapping("/load")
    public Object deserialize(@RequestParam String path) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        return ois.readObject();
    }

    @PostMapping("/config")
    public Object yaml(@RequestParam String body) {
        Yaml yaml = new Yaml();
        return yaml.load(body);
    }

    @PostMapping("/xmlconfig")
    public Object xmlDecode(@RequestParam String path) throws Exception {
        XMLDecoder decoder = new XMLDecoder(new FileInputStream(path));
        return decoder.readObject();
    }

    @PostMapping("/xml")
    public void parseXml() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder();
    }

    @GetMapping("/class")
    public Object loadPlugin(@RequestParam String className) throws Exception {
        return Class.forName(className).getDeclaredConstructor().newInstance();
    }

    @GetMapping("/validate")
    public boolean redos(@RequestParam String input) {
        return Pattern.compile("^(a+)+$").matcher(input).matches();
    }

    public void extract(ZipInputStream zis, File targetDir) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File dest = new File(targetDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(dest);
        }
    }
}
