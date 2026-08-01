package run.halo.fixture;

import org.yaml.snakeyaml.Yaml;

/**
 * Version-gate fixture: a bare `new Yaml()`. The sibling pom.xml declares
 * SnakeYAML 2.2, which rejects global type tags by default, so this is
 * informational — unlike UnsafeYaml.java in the same directory, which passes
 * a permissive Constructor and stays CRITICAL.
 */
public class PlainYaml {

    public Object parse(String text) {
        Yaml yaml = new Yaml();
        return yaml.load(text);
    }
}
