package run.halo.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

/**
 * Positive fixture (RC2): default typing enabled on a real Jackson
 * ObjectMapper with the permissive validator — JS501 must fire.
 */
public class LaissezFaireMapper {

    public ObjectMapper build() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);
        return mapper;
    }

    public ObjectMapper legacy() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper;
    }
}
