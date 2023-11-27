package com.hdfc.Services.Repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.hdfc.Services.Model.Service;
import com.hdfc.Services.dto.ServiceRequestResponse;

@Repository
public interface ServiceRepository extends JpaRepository<Service, Integer> {

	@Query("select new com.hdfc.Services.dto.ServiceRequestResponse(servreq.customerid,servreq.branchid,serv.name,servreq.employeeid,servreq.status,servreq.starttime,servreq.endtime) from Service serv join serv.servicerequest servreq where servreq.branchid=:id")
	List<ServiceRequestResponse> getAllServicerequestPerBranch(@Param("id") int id);

	@Query("select new com.hdfc.Services.dto.ServiceRequestResponse(servreq.customerid,servreq.branchid,serv.name,servreq.employeeid,servreq.status,servreq.starttime,servreq.endtime) from Service serv join serv.servicerequest servreq")
	List<ServiceRequestResponse> getAllServicerequest();
	
	@Query("select new com.hdfc.Services.dto.ServiceRequestResponse(servreq.customerid,servreq.branchid,serv.name,servreq.employeeid,servreq.status,servreq.starttime,servreq.endtime) from Service serv join serv.servicerequest servreq where servreq.status=:status and servreq.branchid=:id")
	List<ServiceRequestResponse> getAllCompletedServicerequestPerBranch(@Param("status") String status,@Param("id") int id);

	@Query("select new com.hdfc.Services.dto.ServiceRequestResponse(servreq.customerid,servreq.branchid,serv.name,servreq.employeeid,servreq.status,servreq.starttime,servreq.endtime) from Service serv join serv.servicerequest servreq where servreq.status=:status and servreq.branchid=:id")
	List<ServiceRequestResponse> getAllPendingServicerequestPerBranch(@Param("status") String status,@Param("id") int id);


}
