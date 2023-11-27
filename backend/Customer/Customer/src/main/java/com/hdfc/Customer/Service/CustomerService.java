package com.hdfc.Customer.Service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.hdfc.Customer.Exception.HandleBadRequest;
import com.hdfc.Customer.Repository.CustomerRepository;
import com.hdfc.Customer.model.Customer;

@Service
public class CustomerService {
	
	@Autowired
	private CustomerRepository customerRepository;

	public List<Customer> getAllCustomer() {
		return customerRepository.findAll();
	}

	public Customer addCustomer(Customer customer) {
		return customerRepository.save(customer);
	}

	public int getTotalCustomerPerBranch(int id) {
		
		return customerRepository.getTotalCustomerPerBranch(id);
	}

	public int getTotalCustomer() {
		
		return customerRepository.getTotalCustomer();
	}

	public String getCustomerNameById(Long bid, Long cid) throws HandleBadRequest{
		
		Customer cust = customerRepository.getCustomerNameAtBranchById(bid,cid);
		if(cust==null) throw new HandleBadRequest("invalid token");;
		return cust.getName();
	}

}
