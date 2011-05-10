package org.signserver.module.wsra.ws;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.xml.ws.handler.MessageContext;

public class WSRATestMessageContext  implements MessageContext{


	private static final long serialVersionUID = 1L;

	HashMap<String,Object> map = new HashMap<String,Object>();
	
	@SuppressWarnings("unchecked")
	Map m;
	
	public Scope getScope(String arg0) {
		return null;
	}

	
	public void setScope(String arg0, Scope arg1) {
		
	}

	
	public void clear() {
		map.clear();			
	}

	
	public boolean containsKey(Object key) {
		return map.containsKey(key);
	}

	public boolean containsValue(Object value) {			
		return map.containsValue(value);
	}

	public Set<java.util.Map.Entry<String, Object>> entrySet() {
		return map.entrySet();
	}

	public Object get(Object key) {
		return map.get(key);
	}

	public boolean isEmpty() {		
		return map.isEmpty();
	}

	public Set<String> keySet() {
		return map.keySet();
	}

	public Object put(String key, Object value) {
		return map.put(key, value);
	}

	public void putAll(Map<? extends String, ? extends Object> m) {
        map.putAll(m);			
	}

	public Object remove(Object key) {
		return map.remove(key);
	}

	public int size() {
		return map.size();
	}

	public Collection<Object> values() {
		return map.values();
	}

}
