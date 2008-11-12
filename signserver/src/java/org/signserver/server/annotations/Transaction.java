package org.signserver.server.annotations;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation used to mark the transaction method that should
 * be used when accessing the method.
 * 
 * If a method (most commonly used for Web Service methods)
 * should be surrounded with a transaction add this annotation
 * to that method.
 * 
 * Default is TransactionType.Required which means a transaction will be created
 * the other value TransactionType.Supports will not create a transaction but
 * will use a transaction if it already exists.
 * 
 * It must be used with the WorkerEntityManager annotation marking
 * the field used for worker entity manager.
 * 
 * 
 * 
 * @author Philip Vendil 23 okt 2008
 *
 * @version $Id$
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Transaction {
    TransactionType value() default TransactionType.REQUIRED;
}
