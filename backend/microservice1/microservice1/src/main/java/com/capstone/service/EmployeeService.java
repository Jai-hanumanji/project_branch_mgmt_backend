package com.capstone.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.capstone.model.Employee;
import com.capstone.repository.BranchRepository;
import com.capstone.repository.EmployeeRepository;

@Service
public class EmployeeService {
	
	@Autowired
	private EmployeeRepository employeerepository;
	
	@Autowired
	private BranchRepository branchRepository;
	
	public List<Employee> findAllEmployees(){
		return employeerepository.findAll();
		}

	public Optional<Employee> findEmployeeById(int id){
		return employeerepository.findById(id);
	}

	public String getEmployeeNameById(Long bid,Long eid) {
		return branchRepository.getEmployeeNameById(bid,eid);
	}

	public String getBranchNameById(Long bid) {
		return branchRepository.getBranchNameById(bid);
	}
}
