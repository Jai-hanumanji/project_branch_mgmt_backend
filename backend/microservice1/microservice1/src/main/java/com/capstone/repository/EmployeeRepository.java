package com.capstone.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.capstone.model.Employee;

public interface EmployeeRepository extends JpaRepository<Employee, Integer>{

}
