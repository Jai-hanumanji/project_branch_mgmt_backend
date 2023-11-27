package com.capstone.service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.capstone.client.Exception.HandleBadRequest;
import com.capstone.model.Branch;
import com.capstone.repository.BranchRepository;

@Service
public class BranchService {
	
	@Autowired
	private BranchRepository branchrepository;
	
	public List<Branch> findAllBranches(){
		return branchrepository.findAll();
		}
	
	public Branch findBranchById(int id) throws HandleBadRequest {
		
		Branch branch = branchrepository.findById(id).orElse(null);
		if(branch==null) throw new HandleBadRequest("Inavlid branch id");
		return branch;
	}

	public Branch addEmployee(Branch emp) {
		return branchrepository.save(emp);
	}

	public List<Branch> getAllBranch() {
		
		return branchrepository.findAll();
	}
 
}
