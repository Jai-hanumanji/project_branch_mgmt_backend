package com.capstone.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.capstone.model.Branch;

public interface BranchRepository extends JpaRepository<Branch, Integer> {

	@Query("select emp.name from Branch br join br.employee emp where br.id=:bid and emp.id=:eid")
	String getEmployeeNameById(@Param("bid") Long bid,@Param("eid")  Long eid);

	@Query("select br.name from Branch br where br.id=:bid")
	String getBranchNameById(@Param("bid") Long bid);

}
