/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.wsra.core;

import java.util.List;

import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.common.WSRAConstants.PricingStatus;
import org.signserver.module.wsra.common.WSRAConstants.ProductStatus;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ProductManagerTest extends CommonManagerT {

    private static ProductManager pm = null;

    protected void setUp() throws Exception {
        super.setUp();
        if (pm == null) {
            pm = new ProductManager(workerEntityManager);
        }
    }

    public void test01Products() throws Exception {
        ProductDataBean prod1 = new ProductDataBean("123", "Prod 123", "This is a good product");
        ProductDataBean prod2 = new ProductDataBean("124", "Prod 124", "This is not a good product");
        ProductDataBean prod3 = new ProductDataBean("125", "Prod 125", "This is a product");

        tb();
        pm.editProduct(prod1);
        tc();
        tb();
        pm.editProduct(prod2);
        tc();
        tb();
        pm.editProduct(prod3);
        tc();

        ProductDataBean result = pm.findProduct("123");
        assertNotNull(result);
        assertTrue(result.getProductNumber().equals("123"));
        assertTrue(result.getDisplayName().equals("Prod 123"));
        assertTrue(result.getDescription().equals("This is a good product"));
        assertTrue(result.getStatus() == ProductStatus.SOLD);
        int prodId1 = result.getId();

        result = pm.findProduct("124");
        assertNotNull(result);
        assertTrue(result.getProductNumber().equals("124"));
        int prodId2 = result.getId();

        result.setComment("SomeComment");
        result.setStatus(ProductStatus.NOTSOLD);
        tb();
        pm.editProduct(result);
        tc();

        result = pm.findProduct("124");
        assertNotNull(result);
        assertTrue(result.getProductNumber().equals("124"));
        assertTrue(result.getComment().equals("SomeComment"));

        result = pm.findProduct("test123");
        assertNull(result);

        result = pm.findProduct(prodId1);
        assertNotNull(result);
        assertTrue(result.getProductNumber().equals("123"));

        result = pm.findProduct(prodId1 + 123);
        assertNull(result);

        List<ProductDataBean> res = pm.listProducts(null);
        assertTrue(res.size() == 3);

        res = pm.listProducts(ProductStatus.SOLD);
        assertTrue(res.size() == 2);
        res = pm.listProducts(ProductStatus.NOTSOLD);
        assertTrue(res.size() == 1);
        res = pm.listProducts(ProductStatus.ARCHIVED);
        assertTrue(res.size() == 0);

        tb();
        pm.removeProduct(prodId1);
        tc();
        tb();
        pm.removeProduct(prodId1);
        tc();
        tb();
        pm.removeProduct(prodId2);
        tc();
        res = pm.listProducts(null);
        assertTrue(res.size() == 1);

    }

    public void test02Prices() throws Exception {
        PricingDataBean price1 = new PricingDataBean("classA", "Price Class A", (float) 5.0, PricingDataBean.CURRENCY_NOK);
        PricingDataBean price2 = new PricingDataBean("classB", "Price Class B", (float) 4.6, PricingDataBean.CURRENCY_NOK);
        PricingDataBean price3 = new PricingDataBean("classC", "Price Class C", (float) 7, PricingDataBean.CURRENCY_NOK);

        tb();
        pm.editPrice(price1);
        tc();
        tb();
        pm.editPrice(price2);
        tc();
        tb();
        pm.editPrice(price3);
        tc();

        PricingDataBean result = pm.findPrice("classA");
        assertNotNull(result);
        assertTrue(result.getPriceClass().equals("classA"));
        assertTrue(result.getDisplayName().equals("Price Class A"));
        assertTrue(result.getPrice() == 5.0);
        assertTrue(result.getCurrency().equals(PricingDataBean.CURRENCY_NOK));
        assertTrue(result.getStatus() == PricingStatus.ACTIVE);
        int priceId1 = result.getId();

        result = pm.findPrice("classB");
        assertNotNull(result);
        assertTrue(result.getPriceClass().equals("classB"));
        int priceId2 = result.getId();

        result.setComment("SomeComment");
        result.setStatus(PricingStatus.DISABLED);
        tb();
        pm.editPrice(result);
        tc();

        result = pm.findPrice("classB");
        assertNotNull(result);
        assertTrue(result.getPriceClass().equals("classB"));
        assertTrue(result.getComment().equals("SomeComment"));

        result = pm.findPrice("classA123");
        assertNull(result);

        result = pm.findPrice(priceId1);
        assertNotNull(result);
        assertTrue(result.getPriceClass().equals("classA"));

        result = pm.findPrice(priceId1 + 123);
        assertNull(result);

        List<PricingDataBean> res = pm.listPrices(null);
        assertTrue(res.size() == 3);

        res = pm.listPrices(PricingStatus.ACTIVE);
        assertTrue(res.size() == 2);
        res = pm.listPrices(PricingStatus.DISABLED);
        assertTrue(res.size() == 1);
        res = pm.listPrices(PricingStatus.ARCHIVED);
        assertTrue(res.size() == 0);

        tb();
        pm.removePrice(priceId1);
        tc();
        tb();
        pm.removePrice(priceId1);
        tc();
        tb();
        pm.removePrice(priceId2);
        tc();
        res = pm.listPrices(null);
        assertTrue(res.size() == 1);

    }
}
