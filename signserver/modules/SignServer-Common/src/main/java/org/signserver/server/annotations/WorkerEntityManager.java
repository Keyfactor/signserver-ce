package org.signserver.server.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that works the WorkerEntityManager in a Object.
 * 
 * If a Transaction annotation is used in a class MUST this
 * annotation be marking the WorkerEntityManager that
 * should be used. The WorkerEntityManager must also
 * be initialized before any call the the transaction marked
 * method can be called.
 *
 * @author Philip Vendil 23 okt 2008
 * @version $Id$
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface WorkerEntityManager {
}
