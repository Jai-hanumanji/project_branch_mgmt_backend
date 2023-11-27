package com.hdfc.Customer.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.hdfc.Customer.model.Customer;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Long> {

	@Query("select count(distinct name) , cust from Customer cust where cust.branchid=:id")
	int getTotalCustomerPerBranch(@Param("id") int id);

	@Query("select count(distinct name) , cust from Customer cust")
	int getTotalCustomer();
	
	@Query("select cust from Customer cust where cust.branchid=:bid and cust.id=:cid")
	Customer getCustomerNameAtBranchById(@Param("bid") Long bid,@Param("cid") Long cid);

}
