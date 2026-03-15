Select 
    case 
        when activity_type like '%run%' then 'run' 
        when activity_type like '%ride%' then 'ride' 
        else activity_type end as a_type,
        sum(distance)*0.000621371,
        sum(elevation_gain)*3.28084,
        sum(duration)/ 3600.0  
FROM user_activities 
GROUP BY a_type;
