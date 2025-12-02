<?php
 session_start();
if ($_SESSION['role'] !== 'admin') {
    header('Location: ../index.php');
    exit();
}
$employees = true;
include 'backend/actions.php';
fillform();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Details</title>
  <link rel="stylesheet" href="../css/styles.css" />
</head>
<body>
  <div class="dashboard-container">
        <?php
        include 'sidebar.php';
        ?>
        <!-- Main Content -->
        <main class="main-content">
            <!-- Top Header -->
            <?php 
                include 'header.php'
            ;?>

            <!-- Dashboard Content -->
            <div class="dashboard-content">
                <div class="content-grid">
                    
                    
                <main class="main">
                    <header class="topbar">
                    
                    </header>    
                    <form method="post"  class="onboarding-form" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">    
                        <section class="content container">
                            
                                <div style="height:12px"></div>

                                <div class="card">
                                <div class="card-header">
                                    <div class="card-title"><h2>Personal Information</h2></div>
                                    
                                </div>
                                <div class="card-body">
                                    
                                    <?php if(isset($firstnameErr)) echo'<label class="form_error"> '.$firstnameErr.'</label>';?>
                                    <div class="form-row">
                                            <label for="firstname">First Name</label>
                                            <input id="firstname" name="firstname" type="text" placeholder="James"  value="<?php echo $firstname;?>">
                                        </div>

                                        <?php if(isset($lastnameErr)) echo'<label class="form_error"> '.$lastnameErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="lastname" >Last Name</label>
                                            <input id="lastname" name="lastname" type="text" placeholder="Brown" value="<?php echo $lastname;?>">
                                        </div>
                                            
                                        <?php if(isset($birthdateErr)) echo'<label class="form_error"> '.$birthdateErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="birthdate" >Birth date</label>
                                            <input id="birthdate" name="birthdate" type="date" placeholder="mm/dd/yyyy" value="<?php echo $birthdate;?>">
                                        </div>

                                        <?php if(isset($genderErr)) echo'<label class="form_error"> '.$genderErr.'</label>';?>
                                        <div class="form-row">
                                            <label>Gender</label>
                                            <label> 
                                                Male<input type="radio" name="gender" value="M" <?php if($gender == "M") echo'checked=true'?> >
                                                Female<input type="radio" name="gender" value="F" <?php if($gender == "F") echo'checked=true'?> >
                                            </label>
                                        </div>

                                        <?php if(isset($ssnErr)) echo'<label class="form_error"> '.$ssnErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="ssn">SSN</label>
                                            <input id="ssn" name="ssn" type="text" placeholder="123-45-6789" value="<?php echo $ssn;?>"/>
                                        </div>

                                        <?php if(isset($raceErr)) echo'<label class="form_error"> '.$raceErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="race">Race</label>
                                            <select id="race" name="race">
                                                <option value="">-select-</option>
                                                <option value="Asian" <?php if($race == "Asian") echo 'selected'; ?>>Asian</option>
                                                <option value="Black" <?php if($race == "Black") echo 'selected'; ?>>Black or African American</option>
                                                <option value="White" <?php if($race == "White") echo 'selected'; ?>>White</option>
                                                <option value="Hispanic" <?php if($race == "Hispanic") echo 'selected'; ?>>Hispanic or Latino</option>
                                                <option value="Other" <?php if($race == "Other") echo 'selected'; ?>>Other</option>
                                            </select>
                                        </div>

                                        <?php if(isset($emailErr)) echo'<label class="form_error"> '.$emailErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="testemail">Email</label>
                                            <input id="testemail" name="testemail" type="email" placeholder="name@example.com" value="<?php echo $email;?>"/>
                                        </div>

                                        <?php if(isset($phoneErr)) echo'<label class="form_error"> '.$phoneErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="phone">Phone</label>
                                            <input id="phone" name="phone" type="tel" placeholder="123-456-7890" value="<?php echo $phone;?>" />
                                        </div>

                                        <?php if(isset($stateErr)) echo'<label class="form_error"> '.$stateErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="state">State</label>
                                            <select id="state" name="state">
                                                <option value="">-select-</option>
                                                <option value="AL" <?php if($state == "AL") echo 'selected'; ?>>Alabama</option>
                                                <option value="AK" <?php if($state == "AK") echo 'selected'; ?>>Alaska</option>
                                                <option value="AZ" <?php if($state == "AZ") echo 'selected'; ?>>Arizona</option>
                                                <option value="AR" <?php if($state == "AR") echo 'selected'; ?>>Arkansas</option>
                                                <option value="CA" <?php if($state == "CA") echo 'selected'; ?>>California</option>
                                                <option value="CO" <?php if($state == "CO") echo 'selected'; ?>>Colorado</option>
                                                <option value="CT" <?php if($state == "CT") echo 'selected'; ?>>Connecticut</option>
                                                <option value="DE" <?php if($state == "DE") echo 'selected'; ?>>Delaware</option>
                                                <option value="FL" <?php if($state == "FL") echo 'selected'; ?>>Florida</option>
                                                <option value="GA" <?php if($state == "GA") echo 'selected'; ?>>Georgia</option>
                                                <option value="HI" <?php if($state == "HI") echo 'selected'; ?>>Hawaii</option>
                                                <option value="ID" <?php if($state == "ID") echo 'selected'; ?>>Idaho</option>
                                                <option value="IL" <?php if($state == "IL") echo 'selected'; ?>>Illinois</option>
                                                <option value="IN" <?php if($state == "IN") echo 'selected'; ?>>Indiana</option>
                                                <option value="IA" <?php if($state == "IA") echo 'selected'; ?>>Iowa</option>
                                                <option value="KS" <?php if($state == "KS") echo 'selected'; ?>>Kansas</option>
                                                <option value="KY" <?php if($state == "KY") echo 'selected'; ?>>Kentucky</option>
                                                <option value="LA" <?php if($state == "LA") echo 'selected'; ?>>Louisiana</option>
                                                <option value="ME" <?php if($state == "ME") echo 'selected'; ?>>Maine</option>
                                                <option value="MD" <?php if($state == "MD") echo 'selected'; ?>>Maryland</option>
                                                <option value="MA" <?php if($state == "MA") echo 'selected'; ?>>Massachusetts</option>
                                                <option value="MI" <?php if($state == "MI") echo 'selected'; ?>>Michigan</option>
                                                <option value="MN" <?php if($state == "MN") echo 'selected'; ?>>Minnesota</option>
                                                <option value="MS" <?php if($state == "MS") echo 'selected'; ?>>Mississippi</option>
                                                <option value="MO" <?php if($state == "MO") echo 'selected'; ?>>Missouri</option>
                                                <option value="MT" <?php if($state == "MT") echo 'selected'; ?>>Montana</option>
                                                <option value="NE" <?php if($state == "NE") echo 'selected'; ?>>Nebraska</option>
                                                <option value="NV" <?php if($state == "NV") echo 'selected'; ?>>Nevada</option>
                                                <option value="NH" <?php if($state == "NH") echo 'selected'; ?>>New Hampshire</option>
                                                <option value="NJ" <?php if($state == "NJ") echo 'selected'; ?>>New Jersey</option>
                                                <option value="NM" <?php if($state == "NM") echo 'selected'; ?>>New Mexico</option>
                                                <option value="NY" <?php if($state == "NY") echo 'selected'; ?>>New York</option>
                                                <option value="NC" <?php if($state == "NC") echo 'selected'; ?>>North Carolina</option>
                                                <option value="ND" <?php if($state == "ND") echo 'selected'; ?>>North Dakota</option>
                                                <option value="OH" <?php if($state == "OH") echo 'selected'; ?>>Ohio</option>
                                                <option value="OK" <?php if($state == "OK") echo 'selected'; ?>>Oklahoma</option>
                                                <option value="OR" <?php if($state == "OR") echo 'selected'; ?>>Oregon</option>
                                                <option value="PA" <?php if($state == "PA") echo 'selected'; ?>>Pennsylvania</option>
                                                <option value="RI" <?php if($state == "RI") echo 'selected'; ?>>Rhode Island</option>
                                                <option value="SC" <?php if($state == "SC") echo 'selected'; ?>>South Carolina</option>
                                                <option value="SD" <?php if($state == "SD") echo 'selected'; ?>>South Dakota</option>
                                                <option value="TN" <?php if($state == "TN") echo 'selected'; ?>>Tennessee</option>
                                                <option value="TX" <?php if($state == "TX") echo 'selected'; ?>>Texas</option>
                                                <option value="UT" <?php if($state == "UT") echo 'selected'; ?>>Utah</option>
                                                <option value="VT" <?php if($state == "VT") echo 'selected'; ?>>Vermont</option>
                                                <option value="VA" <?php if($state == "VA") echo 'selected'; ?>>Virginia</option>
                                                <option value="WA" <?php if($state == "WA") echo 'selected'; ?>>Washington</option>
                                                <option value="WV" <?php if($state == "WV") echo 'selected'; ?>>West Virginia</option>
                                                <option value="WI" <?php if($state == "WI") echo 'selected'; ?>>Wisconsin</option>
                                                <option value="WY" <?php if($state == "WY") echo 'selected'; ?>>Wyoming</option>
                                            </select>
                                        </div>

                                        <?php if(isset($cityErr)) echo'<label class="form_error"> '.$cityErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="city">City</label>
                                            <input id="city" name="city" type="text" placeholder="Los Angeles" value="<?php echo $city;?>" />
                                        </div>

                                        <?php if(isset($zipcodeErr)) echo'<label class="form_error"> '.$zipcodeErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="zipcode">Zipcode</label>
                                            <input id="zipcode" name="zipcode" type="text" placeholder="12345" value="<?php echo $zipcode; ?>" />
                                        </div>

                                        <?php if(isset($addressErr)) echo'<label class="form_error"> '.$addressErr.'</label>';?>
                                        <div class="form-row">
                                            <label for="address">Address 1</label>
                                            <input id="address" name="address" type="text" value="<?php echo $address; ?>"></textarea>
                                        </div>
                                        <?php if(isset($address2Err)) echo'<label class="form_error"> '.$address2Err.'</label>';?>
                                        <div class="form-row">
                                            <label for="address2">Address 2</label>
                                            <input id="address2" name="address2" type="text" value="<?php echo $address2; ?>"></textarea>
                                        </div>
                                    
                                </div>
                                </div>
                        </section>
                        <div style="height:16px"></div>
                        <section class="content container">
                            
                                <div style="height:12px"></div>

                                <div class="card">
                                    <div class="card-header">
                                        <div class="card-title"><h2>Employment Information</h2></div>
                                        
                                    </div>
                                    <div class="card-body">
                                        <?php if(isset($jobtitleErr)) echo'<label class="form_error"> '.$jobtitleErr.'</label>';?>
                                            <div class="form-row">
                                                <label for="jobtitle" >Job Title</label>
                                                <select id="job-title" name="jobtitle" >
                                                    <option value="">-select-</option>
                                                    <option value= 1 <?php if($jobtitle == 1) echo 'selected'; ?>>Owner</option>
                                                    <option value= 2 <?php if($jobtitle == 2) echo 'selected'; ?>>General Manager</option>
                                                    <option value= 3 <?php if($jobtitle == 3) echo 'selected'; ?>>Assistant Manager</option>
                                                    <option value= 4 <?php if($jobtitle == 4) echo 'selected'; ?>>Shift Supervisor</option>
                                                    <option value= 5 <?php if($jobtitle == 5) echo 'selected'; ?>>Sales Associate</option>
                                                    <option value= 6 <?php if($jobtitle == 6) echo 'selected'; ?>>Barista</option>
                                                    <option value= 7 <?php if($jobtitle == 7) echo 'selected'; ?>>Cook</option>
                                                    <option value= 8  <?php if($jobtitle == 8) echo 'selected'; ?>>Cashier</option>
                                                    <option value= 9 <?php if($jobtitle == 9) echo 'selected'; ?>>Janitor</option>
                                                    <option value= 10 <?php if($jobtitle == 10) echo 'selected'; ?>>Bookkeeper</option>
                                                </select>
                                            </div>

                                            <?php if(isset($divisionErr)) echo'<label class="form_error"> '.$divisionErr.'</label>';?>
                                            <div class="form-row">
                                                <label for="division" >Division</label>
                                                <select id="division" name="division"  >
                                                    <option value="">-select-</option>
                                                    <option value= 1 <?php if($division == 1) echo 'selected'; ?>>Administration</option>
                                                    <option value= 2 <?php if($division == 2) echo 'selected'; ?>>Management</option>
                                                    <option value= 3 <?php if($division == 3) echo 'selected'; ?>>Front of House</option>
                                                    <option value= 4 <?php if($division == 4) echo 'selected'; ?>>Back of House</option>
                                                </select>
                                            </div>

                                            <?php if(isset($hiredateErr)) echo'<label class="form_error"> '.$hiredateErr.'</label>';?>
                                            <div class="form-row">
                                                <label for="hiredate" >Hire Date</label>
                                                <input id="hiredate" name="hiredate" type="date" placeholder="mm/dd/yyyy" value="<?php echo $hiredate;?>"/>
                                            </div>

                                            <?php if(isset($salaryErr)) echo'<label class="form_error"> '.$salaryErr.'</label>';?>
                                            <div class="form-row">
                                                <label for="salary">Salary</label>
                                                <input id="salary" name="salary" type="text" placeholder="1000" value="<?php echo $salary;?>" />
                                            </div>
                                    </div>
                                </div>

                             
                        </section>
                        <div style="height:16px"></div>
                        <div class="form-actions" style="text-align:center;">
                            <button class="btn" style="color: red;" type="submit" name="terminateemployee">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                                    stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                    stroke-linejoin="round" style="margin-right:8px">
                                <rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect>
                                <rect x="9" y="9" width="6" height="6" fill="currentColor"></rect>
                                </svg>
                                Terminate
                            </button>
                            <button class="btn" name="updateemployee" type="submit">Update</button>
                            <button class="btn ghost" >Cancel</button>   
                        </div>
                    </form>
                        
                </main>

                   

                 


                   
                   
                </div>
            </div>
        </main>
    </div>  

</body>
</html>
